/**
 * @file
 *
 * HKDF against the committed file, and the length contract.
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
  uint32_t hash;
  size_t digest_len;
  std::vector<unsigned char> ikm;
  std::vector<unsigned char> salt;
  std::vector<unsigned char> info;
  std::vector<unsigned char> prk;
  std::vector<unsigned char> okm;
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

bool hash_id(const std::string & name, uint32_t * id, size_t * digest_len) {
  if (name == "sha1") {
    *id = GSEC_HKDF_SHA1;
    *digest_len = GSEC_SHA1_DIGEST_LEN;
    return true;
  }
  if (name == "sha256") {
    *id = GSEC_HKDF_SHA256;
    *digest_len = GSEC_SHA256_DIGEST_LEN;
    return true;
  }
  if (name == "sha384") {
    *id = GSEC_HKDF_SHA384;
    *digest_len = GSEC_SHA384_DIGEST_LEN;
    return true;
  }
  if (name == "sha512") {
    *id = GSEC_HKDF_SHA512;
    *digest_len = GSEC_SHA512_DIGEST_LEN;
    return true;
  }
  return false;
}

bool parse_file(const std::string & text, std::vector<Case> * cases,
    std::string * error) {
  cases->clear();
  std::istringstream in(text);
  std::string line;
  bool saw_primitive = false;
  Case current;
  bool in_case = false;
  bool saw_hash = false;
  bool saw_ikm = false;
  bool saw_salt = false;
  bool saw_info = false;
  bool saw_prk = false;
  bool saw_okm = false;

  auto finish = [&]() -> bool {
    if (!in_case) {
      return true;
    }
    if (current.name.empty() || !saw_hash || !saw_ikm || !saw_salt ||
        !saw_info || !saw_prk || !saw_okm) {
      *error = "truncated case " + current.name;
      return false;
    }
    if (current.prk.size() != current.digest_len || current.okm.empty()) {
      *error = "length in " + current.name;
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
      if (saw_primitive || value != "hkdf") {
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
      saw_hash = saw_ikm = saw_salt = saw_info = saw_prk = saw_okm = false;
      continue;
    }
    if (!in_case || value.empty()) {
      *error = "orphan field";
      return false;
    }
    if (key == "hash") {
      if (saw_hash || !hash_id(value, &current.hash, &current.digest_len)) {
        *error = "hash in " + current.name;
        return false;
      }
      saw_hash = true;
      continue;
    }
    if (key == "ikm") {
      if (saw_ikm || !parse_hex(value, &current.ikm)) {
        *error = "ikm in " + current.name;
        return false;
      }
      saw_ikm = true;
      continue;
    }
    if (key == "salt") {
      if (saw_salt || !parse_hex(value, &current.salt)) {
        *error = "salt in " + current.name;
        return false;
      }
      saw_salt = true;
      continue;
    }
    if (key == "info") {
      if (saw_info || !parse_hex(value, &current.info)) {
        *error = "info in " + current.name;
        return false;
      }
      saw_info = true;
      continue;
    }
    if (key == "prk") {
      if (saw_prk || !parse_hex(value, &current.prk)) {
        *error = "prk in " + current.name;
        return false;
      }
      saw_prk = true;
      continue;
    }
    if (key == "okm") {
      if (saw_okm || !parse_hex(value, &current.okm)) {
        *error = "okm in " + current.name;
        return false;
      }
      saw_okm = true;
      continue;
    }
    *error = "unknown field";
    return false;
  }
  if (!saw_primitive) {
    *error = "primitive missing";
    return false;
  }
  return finish();
}

std::string load_committed() {
  std::ifstream in(std::string(GSEC_TEST_DATA) + "/vectors/hkdf.vec");
  std::ostringstream buf;
  buf << in.rdbuf();
  return buf.str();
}

const unsigned char * bytes_or_null(const std::vector<unsigned char> & v) {
  return v.empty() ? nullptr : v.data();
}

}  /* namespace */

TEST(Hkdf, CommittedFileMatchesExtractExpandAndCombined) {
  std::string error;
  std::vector<Case> cases;
  ASSERT_TRUE(parse_file(load_committed(), &cases, &error)) << error;
  ASSERT_GE(cases.size(), 4u);
  for (const Case & item : cases) {
    std::vector<unsigned char> prk(item.digest_len);
    std::vector<unsigned char> expanded(item.okm.size());
    std::vector<unsigned char> combined(item.okm.size());
    SCOPED_TRACE(item.name);
    ASSERT_EQ(gsec_hkdf_extract(item.hash, bytes_or_null(item.salt),
        item.salt.size(), bytes_or_null(item.ikm), item.ikm.size(), prk.data()),
        GSEC_OK);
    EXPECT_EQ(gsec_equal(prk.data(), item.prk.data(), item.digest_len), GSEC_OK);
    ASSERT_EQ(gsec_hkdf_expand(item.hash, item.prk.data(), item.prk.size(),
        bytes_or_null(item.info), item.info.size(), expanded.data(),
        expanded.size()), GSEC_OK);
    EXPECT_EQ(gsec_equal(expanded.data(), item.okm.data(), item.okm.size()),
        GSEC_OK);
    ASSERT_EQ(gsec_hkdf(item.hash, bytes_or_null(item.salt), item.salt.size(),
        bytes_or_null(item.ikm), item.ikm.size(), bytes_or_null(item.info),
        item.info.size(), combined.data(), combined.size()), GSEC_OK);
    EXPECT_EQ(gsec_equal(combined.data(), item.okm.data(), item.okm.size()),
        GSEC_OK);
    EXPECT_EQ(gsec_wipe(prk.data(), prk.size()), GSEC_OK);
    EXPECT_EQ(gsec_wipe(expanded.data(), expanded.size()), GSEC_OK);
    EXPECT_EQ(gsec_wipe(combined.data(), combined.size()), GSEC_OK);
  }
}

TEST(Hkdf, AMissingSaltIsHashLenZerosAndALongOutputIsLimit) {
  static const unsigned char ikm[3] = {0x61, 0x62, 0x63};
  unsigned char zeros[GSEC_SHA256_DIGEST_LEN];
  unsigned char a[16];
  unsigned char b[16];
  unsigned char too[1];

  std::memset(zeros, 0, sizeof zeros);
  ASSERT_EQ(gsec_hkdf(GSEC_HKDF_SHA256, nullptr, 0, ikm, sizeof ikm, nullptr, 0,
      a, sizeof a), GSEC_OK);
  ASSERT_EQ(gsec_hkdf(GSEC_HKDF_SHA256, zeros, sizeof zeros, ikm, sizeof ikm,
      nullptr, 0, b, sizeof b), GSEC_OK);
  EXPECT_EQ(gsec_equal(a, b, sizeof a), GSEC_OK);
  EXPECT_EQ(gsec_hkdf(GSEC_HKDF_SHA256, nullptr, 0, ikm, sizeof ikm, nullptr, 0,
      too, 255u * GSEC_SHA256_DIGEST_LEN + 1u), GSEC_ERR_LIMIT);
  EXPECT_EQ(gsec_hkdf(0, nullptr, 0, ikm, sizeof ikm, nullptr, 0, a, sizeof a),
      GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_hkdf_extract(GSEC_HKDF_SHA256, nullptr, 1, ikm, sizeof ikm, a),
      GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_hkdf(GSEC_HKDF_SHA256, nullptr, 0, ikm, sizeof ikm, nullptr, 0,
      nullptr, 0), GSEC_OK);
  EXPECT_EQ(gsec_wipe(a, sizeof a), GSEC_OK);
  EXPECT_EQ(gsec_wipe(b, sizeof b), GSEC_OK);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
