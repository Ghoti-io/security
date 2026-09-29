/**
 * @file
 *
 * RSA signing against signatures OpenSSL 3.5.7 verifies.
 *
 * The signature is the encoded message raised to the private exponent.
 * Blinding has to leave those bytes unchanged. A private exponent that is
 * zero, or not strictly below the modulus, is not a key.
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
  /* Initialised, because `finish()` below reads `pss` to decide how many
   * fields a case needs, and on the first `case` line it runs before anything
   * has set it. Valgrind reported that as a conditional jump on an
   * uninitialised value; it was right, and it had nothing to do with the
   * library. */
  bool pss = false;
  uint32_t hash = 0;
  uint32_t mgf = 0;
  std::vector<unsigned char> n;
  std::vector<unsigned char> e;
  std::vector<unsigned char> d;
  std::vector<unsigned char> msg;
  std::vector<unsigned char> salt;
  std::vector<unsigned char> sig;
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

bool hash_id(const std::string & name, uint32_t * id) {
  if (name == "md5") {
    *id = GSEC_RSA_MD5;
  } else if (name == "sha1") {
    *id = GSEC_RSA_SHA1;
  } else if (name == "sha256") {
    *id = GSEC_RSA_SHA256;
  } else if (name == "sha384") {
    *id = GSEC_RSA_SHA384;
  } else if (name == "sha512") {
    *id = GSEC_RSA_SHA512;
  } else {
    return false;
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
    int need = current.pss ? 9 : 7;
    if (current.name.empty() || saw != need || current.sig.empty()) {
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
      if (saw_primitive || value != "rsa_private") {
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
    if (key == "scheme") {
      if (value == "pkcs1") {
        current.pss = false;
      } else if (value == "pss") {
        current.pss = true;
      } else {
        *error = "scheme";
        return false;
      }
    } else if (key == "hash") {
      if (!hash_id(value, &current.hash)) {
        *error = "hash";
        return false;
      }
    } else if (key == "mgf") {
      if (!hash_id(value, &current.mgf)) {
        *error = "mgf";
        return false;
      }
    } else if (key == "salt") {
      if (!parse_hex(value, &current.salt)) {
        *error = "salt";
        return false;
      }
    } else if (key == "n") {
      if (!parse_hex(value, &current.n)) {
        *error = "n";
        return false;
      }
    } else if (key == "e") {
      if (!parse_hex(value, &current.e)) {
        *error = "e";
        return false;
      }
    } else if (key == "d") {
      if (!parse_hex(value, &current.d)) {
        *error = "d";
        return false;
      }
    } else if (key == "msg") {
      if (!parse_hex(value, &current.msg)) {
        *error = "msg";
        return false;
      }
    } else if (key == "sig") {
      if (!parse_hex(value, &current.sig)) {
        *error = "sig";
        return false;
      }
    } else {
      *error = "unknown field";
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

std::string load_file() {
  std::ifstream in(std::string(GSEC_TEST_DATA) + "/vectors/rsa_private.vec");
  std::ostringstream buf;
  buf << in.rdbuf();
  return buf.str();
}

const unsigned char * bytes(const std::vector<unsigned char> & v) {
  return v.empty() ? nullptr : v.data();
}

GSEC_Result sign(const Case & item, unsigned char * sig, size_t sig_len) {
  if (item.pss) {
    return gsec_rsa_private_pss_sign(item.hash, item.mgf, item.n.data(),
        item.n.size(), item.e.data(), item.e.size(), item.d.data(),
        item.d.size(), bytes(item.msg), item.msg.size(), sig, sig_len,
        bytes(item.salt), item.salt.size());
  }
  return gsec_rsa_private_pkcs1_v15_sign(item.hash, item.n.data(),
      item.n.size(), item.e.data(), item.e.size(), item.d.data(),
      item.d.size(), bytes(item.msg), item.msg.size(), sig, sig_len);
}

GSEC_Result verify(const Case & item, const unsigned char * sig, size_t sig_len) {
  if (item.pss) {
    return gsec_rsa_pss_verify(item.hash, item.mgf, item.n.data(),
        item.n.size(), item.e.data(), item.e.size(), bytes(item.msg),
        item.msg.size(), sig, sig_len, item.salt.size());
  }
  return gsec_rsa_pkcs1_v15_verify(item.hash, item.n.data(), item.n.size(),
      item.e.data(), item.e.size(), bytes(item.msg), item.msg.size(), sig,
      sig_len);
}

}  /* namespace */

TEST(RsaSign, KnownAnswersAreThePrivateExponent) {
  std::string error;
  std::vector<Case> cases;
  ASSERT_TRUE(parse_file(load_file(), &cases, &error)) << error;
  ASSERT_EQ(cases.size(), 8u);
  for (const Case & item : cases) {
    SCOPED_TRACE(item.name);
    std::vector<unsigned char> sig(item.sig.size());
    std::vector<unsigned char> again(item.sig.size());
    ASSERT_EQ(sign(item, sig.data(), sig.size()), GSEC_OK);
    EXPECT_EQ(sig, item.sig);
    EXPECT_EQ(verify(item, sig.data(), sig.size()), GSEC_OK);
    ASSERT_EQ(sign(item, again.data(), again.size()), GSEC_OK);
    EXPECT_EQ(again, sig);
  }
}

TEST(RsaSign, LeadingZerosAndAnAliasedBuffer) {
  std::string error;
  std::vector<Case> cases;
  ASSERT_TRUE(parse_file(load_file(), &cases, &error)) << error;
  ASSERT_GT(cases.size(), 2u);
  const Case & item = cases[2];
  ASSERT_EQ(item.n.size(), 64u);
  std::vector<unsigned char> n = {0x00};
  std::vector<unsigned char> e = {0x00};
  std::vector<unsigned char> d = {0x00};
  n.insert(n.end(), item.n.begin(), item.n.end());
  e.insert(e.end(), item.e.begin(), item.e.end());
  d.insert(d.end(), item.d.begin(), item.d.end());
  std::vector<unsigned char> sig(item.sig.size());
  EXPECT_EQ(gsec_rsa_private_pkcs1_v15_sign(item.hash, n.data(), n.size(),
      e.data(), e.size(), d.data(), d.size(), bytes(item.msg), item.msg.size(),
      sig.data(), sig.size()), GSEC_OK);
  EXPECT_EQ(sig, item.sig);

  std::vector<unsigned char> aliased(item.sig.size(), 0);
  std::memcpy(aliased.data(), item.msg.data(), item.msg.size());
  EXPECT_EQ(gsec_rsa_private_pkcs1_v15_sign(item.hash, item.n.data(),
      item.n.size(), item.e.data(), item.e.size(), item.d.data(),
      item.d.size(), aliased.data(), item.msg.size(), aliased.data(),
      aliased.size()), GSEC_OK);
  EXPECT_EQ(aliased, item.sig);

  std::vector<unsigned char> empty;
  EXPECT_EQ(gsec_rsa_private_pss_sign(GSEC_RSA_SHA256, GSEC_RSA_SHA256,
      item.n.data(), item.n.size(), item.e.data(), item.e.size(),
      item.d.data(), item.d.size(), bytes(item.msg), item.msg.size(),
      sig.data(), sig.size(), nullptr, 0), GSEC_OK);
  EXPECT_EQ(gsec_rsa_pss_verify(GSEC_RSA_SHA256, GSEC_RSA_SHA256, item.n.data(),
      item.n.size(), item.e.data(), item.e.size(), bytes(item.msg),
      item.msg.size(), sig.data(), sig.size(), 0), GSEC_OK);
  EXPECT_EQ(gsec_rsa_private_pss_sign(GSEC_RSA_SHA256, GSEC_RSA_SHA256,
      item.n.data(), item.n.size(), item.e.data(), item.e.size(),
      item.d.data(), item.d.size(), bytes(item.msg), item.msg.size(),
      sig.data(), sig.size(), nullptr, 0), GSEC_OK);
  empty.assign(sig.begin(), sig.end());
  EXPECT_EQ(gsec_rsa_private_pss_sign(GSEC_RSA_SHA256, GSEC_RSA_SHA256,
      item.n.data(), item.n.size(), item.e.data(), item.e.size(),
      item.d.data(), item.d.size(), bytes(item.msg), item.msg.size(),
      sig.data(), sig.size(), nullptr, 0), GSEC_OK);
  EXPECT_EQ(sig, empty);
}

TEST(RsaSign, RejectsABadPrivateKey) {
  std::string error;
  std::vector<Case> cases;
  ASSERT_TRUE(parse_file(load_file(), &cases, &error)) << error;
  ASSERT_GT(cases.size(), 2u);
  const Case & item = cases[2];
  ASSERT_EQ(item.n.size(), 64u);
  unsigned char sig[64];
  unsigned char zero[1] = {0x00};
  unsigned char even[1] = {0x02};
  unsigned char one[1] = {0x01};
  unsigned char msg[1] = {0x61};
  unsigned char huge[GSEC_RSA_MODULUS_MAX + 9u];
  std::memset(sig, 0xa5, sizeof sig);
  std::memset(huge, 0x01, sizeof huge);
  EXPECT_EQ(gsec_rsa_private_pkcs1_v15_sign(item.hash, item.n.data(),
      item.n.size(), item.e.data(), item.e.size(), item.d.data(),
      item.d.size(), bytes(item.msg), item.msg.size(), sig, 1),
      GSEC_ERR_INVALID);
  EXPECT_EQ(sig[0], 0xa5);
  EXPECT_EQ(gsec_rsa_private_pkcs1_v15_sign(item.hash, item.n.data(),
      item.n.size(), item.e.data(), item.e.size(), nullptr, item.d.size(),
      bytes(item.msg), item.msg.size(), sig, item.sig.size()),
      GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_rsa_private_pkcs1_v15_sign(item.hash, item.n.data(),
      item.n.size(), item.e.data(), item.e.size(), zero, sizeof zero,
      bytes(item.msg), item.msg.size(), sig, item.sig.size()),
      GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_rsa_private_pkcs1_v15_sign(item.hash, item.n.data(),
      item.n.size(), item.e.data(), item.e.size(), item.n.data(),
      item.n.size(), bytes(item.msg), item.msg.size(), sig, item.sig.size()),
      GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_rsa_private_pkcs1_v15_sign(item.hash, even, sizeof even,
      item.e.data(), item.e.size(), item.d.data(), item.d.size(), nullptr, 0,
      sig, sizeof even), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_rsa_private_pkcs1_v15_sign(item.hash, item.n.data(),
      item.n.size(), one, sizeof one, item.d.data(), item.d.size(), nullptr, 0,
      sig, item.sig.size()), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_rsa_private_pkcs1_v15_sign(99, item.n.data(), item.n.size(),
      item.e.data(), item.e.size(), item.d.data(), item.d.size(), nullptr, 0,
      sig, item.sig.size()), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_rsa_private_pkcs1_v15_sign(item.hash, item.n.data(),
      item.n.size(), item.e.data(), item.e.size(), item.d.data(),
      item.d.size(), nullptr, 1, sig, item.sig.size()), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_rsa_private_pkcs1_v15_sign(item.hash, nullptr, item.n.size(),
      item.e.data(), item.e.size(), item.d.data(), item.d.size(), nullptr, 0,
      sig, item.sig.size()), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_rsa_private_pkcs1_v15_sign(GSEC_RSA_SHA512, item.n.data(),
      item.n.size(), item.e.data(), item.e.size(), item.d.data(),
      item.d.size(), msg, sizeof msg, sig, item.sig.size()), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_rsa_private_pkcs1_v15_sign(item.hash, huge, sizeof huge,
      item.e.data(), item.e.size(), item.d.data(), item.d.size(), nullptr, 0,
      sig, sizeof huge), GSEC_ERR_LIMIT);
  EXPECT_EQ(gsec_rsa_private_pss_sign(item.hash, item.mgf, item.n.data(),
      item.n.size(), item.e.data(), item.e.size(), item.d.data(),
      item.d.size(), bytes(item.msg), item.msg.size(), sig, item.sig.size(),
      nullptr, 4), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_rsa_private_pss_sign(item.hash, item.mgf, item.n.data(),
      item.n.size(), item.e.data(), item.e.size(), item.d.data(),
      item.d.size(), bytes(item.msg), item.msg.size(), nullptr, item.sig.size(),
      nullptr, 0), GSEC_ERR_INVALID);
}

TEST(RsaSign, AWrongPrivateExponentIsCaughtRatherThanSigned) {
  /* rsa_blinded verifies its own output with the public exponent before
   * returning, and gives up after eight attempts. That check is the defence
   * against a fault during the exponentiation and against a blinding factor
   * that does not invert, and nothing exercised it: forcing bn_same to return
   * true left `make test` passing, and the GSEC_ERR_INTERNAL arm had never
   * once executed.
   *
   * A private exponent that is in range but is not the key's is the reachable
   * way in. s^e cannot equal m, every attempt fails the check, and the caller
   * gets GSEC_ERR_INTERNAL rather than a signature that does not verify. */
  std::vector<Case> cases;
  std::string error;
  ASSERT_TRUE(parse_file(load_file(), &cases, &error)) << error;
  ASSERT_FALSE(cases.empty());
  const Case & c = cases[0];
  std::vector<unsigned char> wrong = c.d;
  std::vector<unsigned char> sig(c.n.size());
  ASSERT_GT(wrong.size(), 0u);
  wrong[wrong.size() - 1u] = static_cast<unsigned char>(
      wrong[wrong.size() - 1u] ^ 0x02u);

  EXPECT_EQ(gsec_rsa_private_pkcs1_v15_sign(GSEC_RSA_SHA256, c.n.data(),
      c.n.size(), c.e.data(), c.e.size(), wrong.data(), wrong.size(), "abc", 3,
      sig.data(), sig.size()), GSEC_ERR_INTERNAL);
  /* And the buffer is wiped, so a caller that ignores the status does not
   * transmit whatever the arithmetic produced. */
  for (size_t i = 0; i < sig.size(); i++) {
    EXPECT_EQ(sig[i], 0u) << "signature byte " << i << " survived the failure";
  }

  EXPECT_EQ(gsec_rsa_private_pss_sign(GSEC_RSA_SHA256, GSEC_RSA_SHA256,
      c.n.data(), c.n.size(), c.e.data(), c.e.size(), wrong.data(),
      wrong.size(), "abc", 3, sig.data(), sig.size(), nullptr, 0),
      GSEC_ERR_INTERNAL);

  /* The control: the same call with the real exponent succeeds and verifies.
   * Without it, GSEC_ERR_INTERNAL might be coming from anywhere. */
  EXPECT_EQ(gsec_rsa_private_pkcs1_v15_sign(GSEC_RSA_SHA256, c.n.data(),
      c.n.size(), c.e.data(), c.e.size(), c.d.data(), c.d.size(), "abc", 3,
      sig.data(), sig.size()), GSEC_OK);
  EXPECT_EQ(gsec_rsa_pkcs1_v15_verify(GSEC_RSA_SHA256, c.n.data(), c.n.size(),
      c.e.data(), c.e.size(), "abc", 3, sig.data(), sig.size()), GSEC_OK);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
