/**
 * @file
 *
 * P-256 ECDH against one Wycheproof vector.
 *
 * A coordinate that is not strictly less than the prime, and a point that
 * is not on the curve, are rejected and the output is wiped.
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
  std::vector<unsigned char> peer;
  std::vector<unsigned char> shared;
  std::vector<unsigned char> pub;
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
    if (current.name.empty() || saw != 4 ||
        current.scalar.size() != GSEC_P256_LEN ||
        current.peer.size() != GSEC_P256_PUBLIC_LEN ||
        current.shared.size() != GSEC_P256_LEN ||
        current.pub.size() != GSEC_P256_PUBLIC_LEN) {
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
      if (saw_primitive || value != "ecdh_p256") {
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
    } else if (key == "peer") {
      dest = &current.peer;
    } else if (key == "shared") {
      dest = &current.shared;
    } else if (key == "public") {
      dest = &current.pub;
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
  std::ifstream in(std::string(GSEC_TEST_DATA) + "/vectors/ecdh_p256.vec");
  std::ostringstream buf;
  buf << in.rdbuf();
  return buf.str();
}

}  /* namespace */

TEST(EcdhP256, CommittedFileMatches) {
  std::string error;
  std::vector<Case> cases;
  ASSERT_TRUE(parse_file(load_committed(), &cases, &error)) << error;
  ASSERT_EQ(cases.size(), 1u);
  for (const Case & item : cases) {
    unsigned char shared[GSEC_P256_LEN];
    unsigned char pub[GSEC_P256_PUBLIC_LEN];
    unsigned char inplace[GSEC_P256_LEN];
    SCOPED_TRACE(item.name);
    ASSERT_EQ(gsec_ecdh_p256(item.scalar.data(), item.peer.data(), shared),
        GSEC_OK);
    EXPECT_EQ(gsec_equal(shared, item.shared.data(), sizeof shared), GSEC_OK);
    std::memcpy(inplace, item.scalar.data(), sizeof inplace);
    ASSERT_EQ(gsec_ecdh_p256(inplace, item.peer.data(), inplace), GSEC_OK);
    EXPECT_EQ(gsec_equal(inplace, item.shared.data(), sizeof inplace), GSEC_OK);
    ASSERT_EQ(gsec_ecdh_p256_public(item.scalar.data(), pub), GSEC_OK);
    EXPECT_EQ(gsec_equal(pub, item.pub.data(), sizeof pub), GSEC_OK);
    EXPECT_EQ(gsec_wipe(shared, sizeof shared), GSEC_OK);
    EXPECT_EQ(gsec_wipe(pub, sizeof pub), GSEC_OK);
    EXPECT_EQ(gsec_wipe(inplace, sizeof inplace), GSEC_OK);
  }
}

TEST(EcdhP256, ABadFileIsNotASkippedCase) {
  std::string error;
  std::vector<Case> cases;
  EXPECT_FALSE(parse_file("primitive ecdh_p256\ncase x\npeer zz\n",
      &cases, &error));
  EXPECT_TRUE(cases.empty());
}

TEST(EcdhP256, RejectsAPointThatIsNotOnTheCurve) {
  std::string error;
  std::vector<Case> cases;
  unsigned char peer[GSEC_P256_PUBLIC_LEN];
  unsigned char out[GSEC_P256_LEN];
  size_t i;
  static const unsigned char prime[GSEC_P256_LEN] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
  };

  unsigned char pub[GSEC_P256_PUBLIC_LEN];

  ASSERT_TRUE(parse_file(load_committed(), &cases, &error)) << error;
  std::memcpy(peer, cases[0].peer.data(), sizeof peer);
  peer[63] = static_cast<unsigned char>(peer[63] ^ 0x01u);
  std::memset(out, 0xa5, sizeof out);
  EXPECT_EQ(gsec_ecdh_p256(cases[0].scalar.data(), peer, out), GSEC_ERR_INVALID);
  for (i = 0; i < sizeof out; i++) {
    EXPECT_EQ(out[i], 0);
  }
  std::memcpy(peer, prime, sizeof prime);
  std::memcpy(peer + 32, cases[0].peer.data() + 32, 32);
  std::memset(out, 0xa5, sizeof out);
  EXPECT_EQ(gsec_ecdh_p256(cases[0].scalar.data(), peer, out), GSEC_ERR_INVALID);
  for (i = 0; i < sizeof out; i++) {
    EXPECT_EQ(out[i], 0);
  }
  std::memset(peer, 0, sizeof peer);
  std::memset(pub, 0xa5, sizeof pub);
  EXPECT_EQ(gsec_ecdh_p256_public(peer, pub), GSEC_ERR_INVALID);
  for (i = 0; i < sizeof pub; i++) {
    EXPECT_EQ(pub[i], 0);
  }
}

TEST(EcdhP256, NullArgumentsAreInvalid) {
  unsigned char buf[GSEC_P256_PUBLIC_LEN];
  std::memset(buf, 1, sizeof buf);
  EXPECT_EQ(gsec_ecdh_p256(nullptr, buf, buf), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ecdh_p256(buf, nullptr, buf), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ecdh_p256(buf, buf, nullptr), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ecdh_p256_public(nullptr, buf), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ecdh_p256_public(buf, nullptr), GSEC_ERR_INVALID);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
