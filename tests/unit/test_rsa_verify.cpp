/**
 * @file
 *
 * RSA verification against one Wycheproof case and two OpenSSL signatures.
 *
 * PKCS#1 v1.5 accepts only the DER DigestInfo. A flipped signature byte
 * does not verify. An even modulus is not a key.
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
  /* Initialised for the same reason as test_rsa_sign.cpp's: the field count a
   * case needs is read from `pss` before the first case has set anything. */
  uint32_t hash = 0;
  uint32_t mgf = 0;
  size_t salt = 0;
  bool pss = false;
  std::vector<unsigned char> n;
  std::vector<unsigned char> e;
  std::vector<unsigned char> msg;
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
  bool pss = false;
  Case current;
  bool in_case = false;
  int saw = 0;

  auto finish = [&]() -> bool {
    if (!in_case) {
      return true;
    }
    int need = pss ? 7 : 5;
    if (current.name.empty() || saw != need || current.n.empty() ||
        current.e.empty() || current.sig.empty()) {
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
      if (saw_primitive) {
        *error = "primitive";
        return false;
      }
      if (value == "rsa_pkcs1_v15_verify") {
        pss = false;
      } else if (value == "rsa_pss") {
        pss = true;
      } else {
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
      current.pss = pss;
      in_case = true;
      saw = 0;
      continue;
    }
    if (!in_case || value.empty()) {
      *error = "orphan field";
      return false;
    }
    if (key == "hash") {
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
      current.salt = 0;
      for (char c : value) {
        if (c < '0' || c > '9') {
          *error = "salt";
          return false;
        }
        current.salt = current.salt * 10u + static_cast<size_t>(c - '0');
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

std::string load_file(const char * name) {
  std::ifstream in(std::string(GSEC_TEST_DATA) + "/vectors/" + name);
  std::ostringstream buf;
  buf << in.rdbuf();
  return buf.str();
}

GSEC_Result verify(const Case & item) {
  const unsigned char * msg = item.msg.empty() ? nullptr : item.msg.data();
  if (item.pss) {
    return gsec_rsa_pss_verify(item.hash, item.mgf, item.n.data(),
        item.n.size(), item.e.data(), item.e.size(), msg, item.msg.size(),
        item.sig.data(), item.sig.size(), item.salt);
  }
  return gsec_rsa_pkcs1_v15_verify(item.hash, item.n.data(), item.n.size(),
      item.e.data(), item.e.size(), msg, item.msg.size(), item.sig.data(),
      item.sig.size());
}

}  /* namespace */

TEST(RsaVerify, CommittedFilesMatch) {
  std::string error;
  std::vector<Case> pkcs;
  std::vector<Case> pss;
  ASSERT_TRUE(parse_file(load_file("rsa_pkcs1.vec"), &pkcs, &error)) << error;
  ASSERT_TRUE(parse_file(load_file("rsa_pss.vec"), &pss, &error)) << error;
  ASSERT_EQ(pkcs.size(), 3u);
  ASSERT_EQ(pss.size(), 1u);
  for (const Case & item : pkcs) {
    SCOPED_TRACE(item.name);
    EXPECT_EQ(verify(item), GSEC_OK);
  }
  EXPECT_EQ(verify(pss[0]), GSEC_OK);
  pss[0].sig.back() = static_cast<unsigned char>(pss[0].sig.back() ^ 0x01u);
  EXPECT_EQ(verify(pss[0]), GSEC_ERR_MISMATCH);
  pkcs[0].sig.back() = static_cast<unsigned char>(pkcs[0].sig.back() ^ 0x01u);
  EXPECT_EQ(verify(pkcs[0]), GSEC_ERR_MISMATCH);
}

TEST(RsaVerify, ABadFileIsNotASkippedCase) {
  std::string error;
  std::vector<Case> cases;
  EXPECT_FALSE(parse_file("primitive rsa_pkcs1_v15_verify\ncase x\nhash zz\n",
      &cases, &error));
  EXPECT_TRUE(cases.empty());
}

TEST(RsaVerify, RejectsABadKeyAndAShortSignature) {
  std::string error;
  std::vector<Case> cases;
  unsigned char even[2] = {0x00, 0x02};
  unsigned char exp[1] = {0x03};
  unsigned char huge[GSEC_RSA_MODULUS_MAX + 1u];
  ASSERT_TRUE(parse_file(load_file("rsa_pkcs1.vec"), &cases, &error)) << error;
  EXPECT_EQ(gsec_rsa_pkcs1_v15_verify(GSEC_RSA_SHA256, even, sizeof even, exp,
      sizeof exp, nullptr, 0, cases[0].sig.data(), cases[0].sig.size()),
      GSEC_ERR_INVALID);
  exp[0] = 0x01;
  EXPECT_EQ(gsec_rsa_pkcs1_v15_verify(GSEC_RSA_SHA256, cases[0].n.data(),
      cases[0].n.size(), exp, sizeof exp, nullptr, 0, cases[0].sig.data(),
      cases[0].sig.size()), GSEC_ERR_INVALID);
  std::memset(huge, 0x01, sizeof huge);
  EXPECT_EQ(gsec_rsa_pkcs1_v15_verify(GSEC_RSA_SHA256, huge, sizeof huge, exp,
      sizeof exp, nullptr, 0, cases[0].sig.data(), 1), GSEC_ERR_LIMIT);
  EXPECT_EQ(gsec_rsa_pkcs1_v15_verify(GSEC_RSA_SHA256, cases[0].n.data(),
      cases[0].n.size(), cases[0].e.data(), cases[0].e.size(), nullptr, 0,
      cases[0].sig.data(), 1), GSEC_ERR_MISMATCH);
}

TEST(RsaVerify, NullArgumentsAreInvalid) {
  unsigned char n[1] = {0x03};
  unsigned char e[1] = {0x03};
  unsigned char sig[1] = {0x01};
  unsigned char msg[1] = {0x61};
  EXPECT_EQ(gsec_rsa_pkcs1_v15_verify(GSEC_RSA_SHA256, nullptr, 1, e, 1,
      nullptr, 0, sig, 1), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_rsa_pkcs1_v15_verify(GSEC_RSA_SHA256, n, 1, nullptr, 1,
      nullptr, 0, sig, 1), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_rsa_pkcs1_v15_verify(GSEC_RSA_SHA256, n, 1, e, 1, nullptr, 1,
      sig, 1), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_rsa_pkcs1_v15_verify(GSEC_RSA_SHA256, n, 1, e, 1, msg, 1,
      nullptr, 1), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_rsa_pss_verify(GSEC_RSA_SHA256, GSEC_RSA_SHA256, nullptr, 1,
      e, 1, nullptr, 0, sig, 1, 0), GSEC_ERR_INVALID);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
