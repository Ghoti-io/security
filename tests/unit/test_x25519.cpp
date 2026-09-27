/**
 * @file
 *
 * X25519 against the RFC 7748 vectors.
 *
 * The all-zero shared secret is rejected and the output is wiped. The
 * top bit of the u-coordinate does not change the product.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct Case {
  std::string name;
  std::vector<unsigned char> scalar;
  std::vector<unsigned char> point;
  std::vector<unsigned char> shared;
};

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  return -1;
}

bool parse_hex(const std::string & text, std::vector<unsigned char> * out) {
  out->clear();
  if (text.size() % 2 != 0) {
    return false;
  }
  for (size_t i = 0; i < text.size(); i += 2) {
    int hi = hex_value(text[i]);
    int lo = hex_value(text[i + 1]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    out->push_back(static_cast<unsigned char>((hi << 4) | lo));
  }
  return true;
}

bool parse_file(const std::string & text, std::vector<Case> * cases,
    std::string * error) {
  cases->clear();
  std::istringstream in(text);
  std::string line;
  bool saw_primitive = false;
  Case current;
  bool in_case = false;
  int saw = 0;

  auto finish = [&]() -> bool {
    if (!in_case) {
      return true;
    }
    if (current.name.empty() || saw != 3 ||
        current.scalar.size() != GSEC_X25519_LEN ||
        current.point.size() != GSEC_X25519_LEN ||
        current.shared.size() != GSEC_X25519_LEN) {
      *error = "truncated case " + current.name;
      return false;
    }
    cases->push_back(current);
    return true;
  };

  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (line.empty() || line[0] == '#') {
      continue;
    }
    std::istringstream row(line);
    std::string key;
    std::string value;
    row >> key;
    std::getline(row, value);
    if (!value.empty() && value[0] == ' ') {
      value.erase(0, 1);
    }
    if (key == "primitive") {
      if (saw_primitive || value != "x25519") {
        *error = "primitive";
        return false;
      }
      saw_primitive = true;
      continue;
    }
    if (!saw_primitive) {
      *error = "primitive missing";
      return false;
    }
    if (key == "case") {
      if (!finish()) {
        return false;
      }
      current = Case();
      current.name = value;
      in_case = true;
      saw = 0;
      continue;
    }
    if (!in_case || value.empty()) {
      *error = "orphan field";
      return false;
    }
    std::vector<unsigned char> * dest = nullptr;
    if (key == "scalar") {
      dest = &current.scalar;
    } else if (key == "point") {
      dest = &current.point;
    } else if (key == "shared") {
      dest = &current.shared;
    } else {
      *error = "unknown field";
      return false;
    }
    if (!parse_hex(value, dest)) {
      *error = key;
      return false;
    }
    saw++;
  }
  if (!saw_primitive) {
    *error = "primitive missing";
    return false;
  }
  return finish();
}

std::string load_committed() {
  std::ifstream in(std::string(GSEC_TEST_DATA) + "/vectors/x25519.vec");
  std::ostringstream buf;
  buf << in.rdbuf();
  return buf.str();
}

}  /* namespace */

TEST(X25519, CommittedFileMatches) {
  std::string error;
  std::vector<Case> cases;
  ASSERT_TRUE(parse_file(load_committed(), &cases, &error)) << error;
  ASSERT_EQ(cases.size(), 4u);
  for (const Case & item : cases) {
    unsigned char out[GSEC_X25519_LEN];
    unsigned char inplace[GSEC_X25519_LEN];
    SCOPED_TRACE(item.name);
    ASSERT_EQ(gsec_x25519(item.scalar.data(), item.point.data(), out),
        GSEC_OK);
    EXPECT_EQ(gsec_equal(out, item.shared.data(), sizeof out), GSEC_OK);
    std::memcpy(inplace, item.scalar.data(), sizeof inplace);
    ASSERT_EQ(gsec_x25519(inplace, item.point.data(), inplace), GSEC_OK);
    EXPECT_EQ(gsec_equal(inplace, item.shared.data(), sizeof inplace),
        GSEC_OK);
  }
}

TEST(X25519, ABadFileIsNotASkippedCase) {
  std::string error;
  std::vector<Case> cases;
  EXPECT_FALSE(parse_file("primitive x25519\ncase x\npoint zz\n",
      &cases, &error));
  EXPECT_TRUE(cases.empty());
}

TEST(X25519, PublicKeyMatchesTheBasePoint) {
  std::string error;
  std::vector<Case> cases;
  unsigned char out[GSEC_X25519_LEN];
  ASSERT_TRUE(parse_file(load_committed(), &cases, &error)) << error;
  ASSERT_EQ(gsec_x25519_public(cases[0].scalar.data(), out), GSEC_OK);
  EXPECT_EQ(gsec_equal(out, cases[0].shared.data(), sizeof out), GSEC_OK);
}

TEST(X25519, ZeroIsRejectedAndTheTopBitIsIgnored) {
  unsigned char scalar[GSEC_X25519_LEN];
  unsigned char point[GSEC_X25519_LEN];
  unsigned char out[GSEC_X25519_LEN];
  unsigned char masked[GSEC_X25519_LEN];
  unsigned char k[GSEC_X25519_LEN];
  unsigned char u[GSEC_X25519_LEN];
  const char * expect =
      "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51";
  unsigned char want[GSEC_X25519_LEN];
  size_t i;

  for (i = 0; i < sizeof scalar; i++) {
    scalar[i] = static_cast<unsigned char>(i + 1);
    point[i] = 0;
  }
  std::memset(out, 0xa5, sizeof out);
  EXPECT_EQ(gsec_x25519(scalar, point, out), GSEC_ERR_INVALID);
  for (i = 0; i < sizeof out; i++) {
    EXPECT_EQ(out[i], 0);
  }
  EXPECT_EQ(gsec_x25519(nullptr, point, out), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_x25519_public(nullptr, out), GSEC_ERR_INVALID);

  std::string error;
  std::vector<Case> cases;
  ASSERT_TRUE(parse_file(load_committed(), &cases, &error)) << error;
  std::memcpy(point, cases[2].point.data(), sizeof point);
  point[31] = static_cast<unsigned char>(point[31] | 0x80u);
  ASSERT_EQ(gsec_x25519(cases[2].scalar.data(), point, out), GSEC_OK);
  ASSERT_EQ(gsec_x25519(cases[2].scalar.data(), cases[2].point.data(), masked),
      GSEC_OK);
  EXPECT_EQ(gsec_equal(out, masked, sizeof out), GSEC_OK);

  std::memset(k, 0, sizeof k);
  std::memset(u, 0, sizeof u);
  k[0] = 9;
  u[0] = 9;
  for (i = 0; i < 1000; i++) {
    ASSERT_EQ(gsec_x25519(k, u, out), GSEC_OK);
    std::memcpy(u, k, sizeof u);
    std::memcpy(k, out, sizeof k);
  }
  ASSERT_TRUE(parse_hex(expect, &cases[0].shared));
  std::memcpy(want, cases[0].shared.data(), sizeof want);
  EXPECT_EQ(gsec_equal(k, want, sizeof k), GSEC_OK);
  EXPECT_EQ(gsec_wipe(out, sizeof out), GSEC_OK);
  EXPECT_EQ(gsec_wipe(scalar, sizeof scalar), GSEC_OK);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
