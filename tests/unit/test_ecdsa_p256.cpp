/**
 * @file
 *
 * ECDSA P-256 against RFC 6979 appendix A.2.5.
 *
 * Signing emits the low s. Verification accepts the high s the RFC prints.
 * An r or s of zero, or one that is not strictly less than the group
 * order, does not verify.
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
  std::vector<unsigned char> msg;
  std::vector<unsigned char> pub;
  std::vector<unsigned char> sig;
  std::vector<unsigned char> high;
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
    if (current.name.empty() || saw != 5 ||
        current.scalar.size() != GSEC_ECDSA_P256_LEN ||
        current.pub.size() != GSEC_ECDSA_P256_PUBLIC_LEN ||
        current.sig.size() != GSEC_ECDSA_P256_SIG_LEN ||
        current.high.size() != GSEC_ECDSA_P256_SIG_LEN) {
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
      if (saw_primitive || value != "ecdsa_p256") {
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
    } else if (key == "msg") {
      dest = &current.msg;
    } else if (key == "public") {
      dest = &current.pub;
    } else if (key == "sig") {
      dest = &current.sig;
    } else if (key == "high") {
      dest = &current.high;
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
  std::ifstream in(std::string(GSEC_TEST_DATA) + "/vectors/ecdsa_p256.vec");
  std::ostringstream buf;
  buf << in.rdbuf();
  return buf.str();
}

}  /* namespace */

TEST(EcdsaP256, CommittedFileMatches) {
  std::string error;
  std::vector<Case> cases;
  ASSERT_TRUE(parse_file(load_committed(), &cases, &error)) << error;
  ASSERT_EQ(cases.size(), 1u);
  for (const Case & item : cases) {
    unsigned char sig[GSEC_ECDSA_P256_SIG_LEN];
    unsigned char pub[GSEC_ECDSA_P256_PUBLIC_LEN];
    unsigned char inplace[GSEC_ECDSA_P256_SIG_LEN];
    SCOPED_TRACE(item.name);
    ASSERT_EQ(gsec_ecdsa_p256_sign(item.scalar.data(), item.msg.data(),
        item.msg.size(), sig), GSEC_OK);
    EXPECT_EQ(gsec_equal(sig, item.sig.data(), sizeof sig), GSEC_OK);
    ASSERT_EQ(gsec_ecdsa_p256_public(item.scalar.data(), pub), GSEC_OK);
    EXPECT_EQ(gsec_equal(pub, item.pub.data(), sizeof pub), GSEC_OK);
    EXPECT_EQ(gsec_ecdsa_p256_verify(pub, item.msg.data(), item.msg.size(),
        sig), GSEC_OK);
    EXPECT_EQ(gsec_ecdsa_p256_verify(item.pub.data(), item.msg.data(),
        item.msg.size(), item.high.data()), GSEC_OK);
    std::memcpy(inplace, item.scalar.data(), GSEC_ECDSA_P256_LEN);
    ASSERT_EQ(gsec_ecdsa_p256_sign(inplace, item.msg.data(), item.msg.size(),
        inplace), GSEC_OK);
    EXPECT_EQ(gsec_equal(inplace, item.sig.data(), sizeof inplace), GSEC_OK);
    std::memcpy(inplace, item.msg.data(), item.msg.size());
    ASSERT_EQ(gsec_ecdsa_p256_sign(item.scalar.data(), inplace, item.msg.size(),
        inplace), GSEC_OK);
    EXPECT_EQ(gsec_equal(inplace, item.sig.data(), sizeof inplace), GSEC_OK);
    EXPECT_EQ(gsec_wipe(sig, sizeof sig), GSEC_OK);
    EXPECT_EQ(gsec_wipe(pub, sizeof pub), GSEC_OK);
    EXPECT_EQ(gsec_wipe(inplace, sizeof inplace), GSEC_OK);
  }
}

TEST(EcdsaP256, ABadFileIsNotASkippedCase) {
  std::string error;
  std::vector<Case> cases;
  EXPECT_FALSE(parse_file("primitive ecdsa_p256\ncase x\nmsg zz\n",
      &cases, &error));
  EXPECT_TRUE(cases.empty());
}

TEST(EcdsaP256, RejectsZeroAndOutOfRange) {
  std::string error;
  std::vector<Case> cases;
  unsigned char sig[GSEC_ECDSA_P256_SIG_LEN];
  unsigned char pub[GSEC_ECDSA_P256_PUBLIC_LEN];
  unsigned char scalar[GSEC_ECDSA_P256_LEN];
  size_t i;
  static const unsigned char order[GSEC_ECDSA_P256_LEN] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
  };

  ASSERT_TRUE(parse_file(load_committed(), &cases, &error)) << error;
  std::memcpy(sig, cases[0].sig.data(), sizeof sig);
  std::memset(sig + GSEC_ECDSA_P256_LEN, 0, GSEC_ECDSA_P256_LEN);
  EXPECT_EQ(gsec_ecdsa_p256_verify(cases[0].pub.data(), cases[0].msg.data(),
      cases[0].msg.size(), sig), GSEC_ERR_MISMATCH);
  std::memcpy(sig, cases[0].sig.data(), sizeof sig);
  std::memset(sig, 0, GSEC_ECDSA_P256_LEN);
  EXPECT_EQ(gsec_ecdsa_p256_verify(cases[0].pub.data(), cases[0].msg.data(),
      cases[0].msg.size(), sig), GSEC_ERR_MISMATCH);
  std::memcpy(sig, cases[0].sig.data(), sizeof sig);
  std::memcpy(sig + GSEC_ECDSA_P256_LEN, order, sizeof order);
  EXPECT_EQ(gsec_ecdsa_p256_verify(cases[0].pub.data(), cases[0].msg.data(),
      cases[0].msg.size(), sig), GSEC_ERR_MISMATCH);

  std::memset(scalar, 0, sizeof scalar);
  std::memset(pub, 0xa5, sizeof pub);
  EXPECT_EQ(gsec_ecdsa_p256_public(scalar, pub), GSEC_ERR_INVALID);
  for (i = 0; i < sizeof pub; i++) {
    EXPECT_EQ(pub[i], 0);
  }
  std::memset(sig, 0xa5, sizeof sig);
  EXPECT_EQ(gsec_ecdsa_p256_sign(order, cases[0].msg.data(),
      cases[0].msg.size(), sig), GSEC_ERR_INVALID);
  for (i = 0; i < sizeof sig; i++) {
    EXPECT_EQ(sig[i], 0);
  }
}

TEST(EcdsaP256, NullArgumentsAreInvalid) {
  unsigned char buf[GSEC_ECDSA_P256_PUBLIC_LEN];
  unsigned char msg[1] = {0x61};
  std::memset(buf, 1, sizeof buf);
  EXPECT_EQ(gsec_ecdsa_p256_public(nullptr, buf), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ecdsa_p256_public(buf, nullptr), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ecdsa_p256_sign(nullptr, msg, 1, buf), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ecdsa_p256_sign(buf, nullptr, 1, buf), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ecdsa_p256_sign(buf, msg, 1, nullptr), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ecdsa_p256_verify(nullptr, msg, 1, buf), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ecdsa_p256_verify(buf, nullptr, 1, buf), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ecdsa_p256_verify(buf, msg, 1, nullptr), GSEC_ERR_INVALID);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
