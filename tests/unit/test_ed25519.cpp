/**
 * @file
 *
 * Ed25519 against the RFC 8032 vectors.
 *
 * A flipped signature byte, a public key that is not a canonical point,
 * and an S that is not strictly less than the group order are rejected.
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
  std::vector<unsigned char> seed;
  std::vector<unsigned char> msg;
  std::vector<unsigned char> pub;
  std::vector<unsigned char> sig;
  std::string mode;
  std::vector<unsigned char> context;
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
  if (text == "-") {
    return true;
  }
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
        current.seed.size() != GSEC_ED25519_LEN ||
        current.pub.size() != GSEC_ED25519_LEN ||
        current.sig.size() != GSEC_ED25519_SIG_LEN) {
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
      if (saw_primitive || value != "ed25519") {
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
    if (key == "mode") {
      current.mode = value;
      continue;
    }
    if (key == "context") {
      if (!parse_hex(value, &current.context)) {
        *error = key;
        return false;
      }
      continue;
    }
    if (key == "seed") {
      dest = &current.seed;
    } else if (key == "msg") {
      dest = &current.msg;
    } else if (key == "public") {
      dest = &current.pub;
    } else if (key == "sig") {
      dest = &current.sig;
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
  std::ifstream in(std::string(GSEC_TEST_DATA) + "/vectors/ed25519.vec");
  std::ostringstream buf;
  buf << in.rdbuf();
  return buf.str();
}

const unsigned char * bytes_or_null(const std::vector<unsigned char> & v) {
  return v.empty() ? nullptr : v.data();
}

}  /* namespace */

TEST(Ed25519, CommittedFileMatches) {
  std::string error;
  std::vector<Case> cases;
  ASSERT_TRUE(parse_file(load_committed(), &cases, &error)) << error;
  ASSERT_EQ(cases.size(), 5u);
  for (const Case & item : cases) {
    unsigned char pub[GSEC_ED25519_LEN];
    unsigned char sig[GSEC_ED25519_SIG_LEN];
    unsigned char inplace[GSEC_ED25519_SIG_LEN];
    const unsigned char * ctx = bytes_or_null(item.context);
    SCOPED_TRACE(item.name);
    ASSERT_EQ(gsec_ed25519_public(item.seed.data(), pub), GSEC_OK);
    EXPECT_EQ(gsec_equal(pub, item.pub.data(), sizeof pub), GSEC_OK);
    if (item.mode == "ctx") {
      ASSERT_EQ(gsec_ed25519_ctx_sign(item.seed.data(), bytes_or_null(item.msg),
          item.msg.size(), ctx, item.context.size(), sig), GSEC_OK);
      EXPECT_EQ(gsec_equal(sig, item.sig.data(), sizeof sig), GSEC_OK);
      EXPECT_EQ(gsec_ed25519_ctx_verify(item.pub.data(),
          bytes_or_null(item.msg), item.msg.size(), item.sig.data(), ctx,
          item.context.size()), GSEC_OK);
    } else if (item.mode == "ph") {
      ASSERT_EQ(gsec_ed25519_ph_sign(item.seed.data(), bytes_or_null(item.msg),
          item.msg.size(), ctx, item.context.size(), sig), GSEC_OK);
      EXPECT_EQ(gsec_equal(sig, item.sig.data(), sizeof sig), GSEC_OK);
      EXPECT_EQ(gsec_ed25519_ph_verify(item.pub.data(),
          bytes_or_null(item.msg), item.msg.size(), item.sig.data(), ctx,
          item.context.size()), GSEC_OK);
    } else {
      ASSERT_EQ(gsec_ed25519_sign(item.seed.data(), bytes_or_null(item.msg),
          item.msg.size(), sig), GSEC_OK);
      EXPECT_EQ(gsec_equal(sig, item.sig.data(), sizeof sig), GSEC_OK);
      EXPECT_EQ(gsec_ed25519_verify(item.pub.data(), bytes_or_null(item.msg),
          item.msg.size(), item.sig.data()), GSEC_OK);
      std::memcpy(inplace, item.seed.data(), GSEC_ED25519_LEN);
      ASSERT_EQ(gsec_ed25519_sign(inplace, bytes_or_null(item.msg),
          item.msg.size(), inplace), GSEC_OK);
      EXPECT_EQ(gsec_equal(inplace, item.sig.data(), sizeof inplace), GSEC_OK);
    }
    EXPECT_EQ(gsec_wipe(pub, sizeof pub), GSEC_OK);
    EXPECT_EQ(gsec_wipe(sig, sizeof sig), GSEC_OK);
    EXPECT_EQ(gsec_wipe(inplace, sizeof inplace), GSEC_OK);
  }
}

TEST(Ed25519, ABadFileIsNotASkippedCase) {
  std::string error;
  std::vector<Case> cases;
  EXPECT_FALSE(parse_file("primitive ed25519\ncase x\nmsg zz\n",
      &cases, &error));
  EXPECT_TRUE(cases.empty());
}

TEST(Ed25519, RejectsATamperedSignatureAndANonCanonicalS) {
  std::string error;
  std::vector<Case> cases;
  unsigned char sig[GSEC_ED25519_SIG_LEN];
  unsigned char bad_point[GSEC_ED25519_LEN];
  unsigned int carry = 0;
  size_t i;
  static const unsigned char order[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
  };

  ASSERT_TRUE(parse_file(load_committed(), &cases, &error)) << error;

  /* A flipped byte of R: either it is no longer a point on the curve, which
   * is a malformed encoding, or it is a different point and the equation
   * fails. Both are refusals and which one it is depends on the byte. */
  std::memcpy(sig, cases[0].sig.data(), sizeof sig);
  sig[0] = static_cast<unsigned char>(sig[0] ^ 0x01u);
  EXPECT_NE(gsec_ed25519_verify(cases[0].pub.data(), nullptr, 0, sig), GSEC_OK);

  /* S + L is the same scalar modulo L, so a verifier that reduces instead of
   * checking the range would accept it. RFC 8032 section 5.1.7 says the
   * encoding is out of range: not a mismatch, a malformed signature. */
  std::memcpy(sig, cases[0].sig.data(), sizeof sig);
  for (i = 0; i < 32; i++) {
    unsigned int sum = static_cast<unsigned int>(sig[32 + i]) + order[i] + carry;
    sig[32 + i] = static_cast<unsigned char>(sum);
    carry = sum >> 8;
  }
  EXPECT_EQ(carry, 0u);
  EXPECT_EQ(gsec_ed25519_verify(cases[0].pub.data(), nullptr, 0, sig),
      GSEC_ERR_INVALID);

  /* A y coordinate of every one bit is above the field prime. */
  std::memset(bad_point, 0xff, sizeof bad_point);
  EXPECT_EQ(gsec_ed25519_verify(bad_point, nullptr, 0, cases[0].sig.data()),
      GSEC_ERR_INVALID);

  /* The pair that makes the check above mean something, and the one the
   * audit could not write while every refusal returned the same code.
   * `prime` encodes y = p, which reduces to y = 0, and `zero` encodes y = 0
   * canonically. y = 0 is a point on this curve - x^2 = 1 - so `zero`
   * decodes and fails the equation, while `prime` must be refused for its
   * encoding before any equation is considered. Without the range check in
   * ge_decode the two would give the same answer, which is the whole
   * malleability question: one signature, two public keys. */
  {
    unsigned char prime[GSEC_ED25519_LEN];
    unsigned char zero[GSEC_ED25519_LEN];

    std::memset(prime, 0xff, sizeof prime);
    prime[0] = 0xed;
    prime[31] = 0x7f;
    std::memset(zero, 0, sizeof zero);
    EXPECT_EQ(gsec_ed25519_verify(prime, nullptr, 0, cases[0].sig.data()),
        GSEC_ERR_INVALID);
    EXPECT_EQ(gsec_ed25519_verify(zero, nullptr, 0, cases[0].sig.data()),
        GSEC_ERR_MISMATCH);
  }

  EXPECT_EQ(gsec_ed25519_verify(cases[0].pub.data(), "no", 2,
      cases[0].sig.data()), GSEC_ERR_MISMATCH);
}

TEST(Ed25519, NullArgumentsAreInvalid) {
  unsigned char buf[GSEC_ED25519_SIG_LEN];
  std::memset(buf, 0, sizeof buf);
  EXPECT_EQ(gsec_ed25519_public(nullptr, buf), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ed25519_public(buf, nullptr), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ed25519_sign(nullptr, nullptr, 0, buf), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ed25519_sign(buf, nullptr, 1, buf), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ed25519_verify(nullptr, nullptr, 0, buf), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ed25519_verify(buf, nullptr, 0, nullptr), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ed25519_verify(buf, nullptr, 1, buf), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ed25519_ctx_sign(buf, nullptr, 0, buf, 256, buf),
      GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ed25519_ph_sign(buf, nullptr, 0, nullptr, 1, buf),
      GSEC_ERR_INVALID);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
