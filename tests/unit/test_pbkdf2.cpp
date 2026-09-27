/**
 * @file
 *
 * PBKDF2 against the committed file, and the iteration contract.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct Case {
  std::string name;
  uint32_t hash;
  std::vector<unsigned char> password;
  std::vector<unsigned char> salt;
  uint32_t iterations;
  std::vector<unsigned char> dk;
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
  if (name == "sha1") {
    *id = GSEC_PBKDF2_SHA1;
    return true;
  }
  if (name == "sha256") {
    *id = GSEC_PBKDF2_SHA256;
    return true;
  }
  if (name == "sha384") {
    *id = GSEC_PBKDF2_SHA384;
    return true;
  }
  if (name == "sha512") {
    *id = GSEC_PBKDF2_SHA512;
    return true;
  }
  return false;
}

bool parse_u32(const std::string & text, uint32_t * out) {
  if (text.empty()) {
    return false;
  }
  uint64_t value = 0;
  for (char c : text) {
    if (c < '0' || c > '9') {
      return false;
    }
    value = value * 10u + static_cast<uint64_t>(c - '0');
    if (value > UINT32_MAX) {
      return false;
    }
  }
  *out = static_cast<uint32_t>(value);
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
  bool saw_hash = false;
  bool saw_password = false;
  bool saw_salt = false;
  bool saw_iterations = false;
  bool saw_dk = false;

  auto finish = [&]() -> bool {
    if (!in_case) {
      return true;
    }
    if (current.name.empty() || !saw_hash || !saw_password || !saw_salt ||
        !saw_iterations || !saw_dk || current.dk.empty() ||
        current.iterations == 0) {
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
      if (saw_primitive || value != "pbkdf2") {
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
      saw_hash = saw_password = saw_salt = saw_iterations = saw_dk = false;
      continue;
    }
    if (!in_case || value.empty()) {
      *error = "orphan field";
      return false;
    }
    if (key == "hash") {
      if (saw_hash || !hash_id(value, &current.hash)) {
        *error = "hash in " + current.name;
        return false;
      }
      saw_hash = true;
      continue;
    }
    if (key == "password") {
      if (saw_password || !parse_hex(value, &current.password)) {
        *error = "password in " + current.name;
        return false;
      }
      saw_password = true;
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
    if (key == "iterations") {
      if (saw_iterations || !parse_u32(value, &current.iterations)) {
        *error = "iterations in " + current.name;
        return false;
      }
      saw_iterations = true;
      continue;
    }
    if (key == "dk") {
      if (saw_dk || !parse_hex(value, &current.dk)) {
        *error = "dk in " + current.name;
        return false;
      }
      saw_dk = true;
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
  std::ifstream in(std::string(GSEC_TEST_DATA) + "/vectors/pbkdf2.vec");
  std::ostringstream buf;
  buf << in.rdbuf();
  return buf.str();
}

const unsigned char * bytes_or_null(const std::vector<unsigned char> & v) {
  return v.empty() ? nullptr : v.data();
}

}  /* namespace */

TEST(Pbkdf2, CommittedFileMatches) {
  std::string error;
  std::vector<Case> cases;
  ASSERT_TRUE(parse_file(load_committed(), &cases, &error)) << error;
  ASSERT_GE(cases.size(), 5u);
  for (const Case & item : cases) {
    std::vector<unsigned char> got(item.dk.size());
    SCOPED_TRACE(item.name);
    ASSERT_EQ(gsec_pbkdf2(item.hash, bytes_or_null(item.password),
        item.password.size(), bytes_or_null(item.salt), item.salt.size(),
        item.iterations, got.data(), got.size()), GSEC_OK);
    EXPECT_EQ(gsec_equal(got.data(), item.dk.data(), item.dk.size()), GSEC_OK);
    EXPECT_EQ(gsec_wipe(got.data(), got.size()), GSEC_OK);
  }
}

TEST(Pbkdf2, ZeroIterationsAreInvalidAndTooManyBlocksAreLimit) {
  static const unsigned char password[8] = {
    0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64
  };
  static const unsigned char salt[4] = {0x73, 0x61, 0x6c, 0x74};
  unsigned char dk[20];
  unsigned char tiny[1];

  EXPECT_EQ(gsec_pbkdf2(GSEC_PBKDF2_SHA1, password, sizeof password, salt,
      sizeof salt, 0, dk, sizeof dk), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_pbkdf2(0, password, sizeof password, salt, sizeof salt, 1, dk,
      sizeof dk), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_pbkdf2(GSEC_PBKDF2_SHA1, nullptr, 1, salt, sizeof salt, 1, dk,
      sizeof dk), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_pbkdf2(GSEC_PBKDF2_SHA1, password, sizeof password, salt,
      sizeof salt, 1, nullptr, 0), GSEC_OK);
  EXPECT_EQ(gsec_pbkdf2(GSEC_PBKDF2_SHA1, password, sizeof password, salt,
      sizeof salt, 1, tiny,
      (static_cast<size_t>(UINT32_MAX) * GSEC_SHA1_DIGEST_LEN) + 1u),
      GSEC_ERR_LIMIT);
  EXPECT_EQ(gsec_wipe(dk, sizeof dk), GSEC_OK);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
