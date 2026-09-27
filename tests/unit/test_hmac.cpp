/**
 * @file
 *
 * HMAC against the committed file, and the contract around verify.
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
  std::vector<unsigned char> key;
  std::vector<unsigned char> msg;
  std::vector<unsigned char> mac;
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
    *id = GSEC_HMAC_SHA1;
    *digest_len = GSEC_SHA1_DIGEST_LEN;
    return true;
  }
  if (name == "sha256") {
    *id = GSEC_HMAC_SHA256;
    *digest_len = GSEC_SHA256_DIGEST_LEN;
    return true;
  }
  if (name == "sha384") {
    *id = GSEC_HMAC_SHA384;
    *digest_len = GSEC_SHA384_DIGEST_LEN;
    return true;
  }
  if (name == "sha512") {
    *id = GSEC_HMAC_SHA512;
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
  bool saw_key = false;
  bool saw_msg = false;
  bool saw_mac = false;

  auto finish = [&]() -> bool {
    if (!in_case) {
      return true;
    }
    if (current.name.empty() || !saw_hash || !saw_key || !saw_msg || !saw_mac) {
      *error = "truncated case " + current.name;
      return false;
    }
    if (current.mac.size() != current.digest_len) {
      *error = "mac length in " + current.name;
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
      if (saw_primitive || value != "hmac") {
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
      saw_hash = saw_key = saw_msg = saw_mac = false;
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
    if (key == "key") {
      if (saw_key || !parse_hex(value, &current.key)) {
        *error = "key in " + current.name;
        return false;
      }
      saw_key = true;
      continue;
    }
    if (key == "msg") {
      if (saw_msg || !parse_hex(value, &current.msg)) {
        *error = "msg in " + current.name;
        return false;
      }
      saw_msg = true;
      continue;
    }
    if (key == "mac") {
      if (saw_mac || !parse_hex(value, &current.mac)) {
        *error = "mac in " + current.name;
        return false;
      }
      saw_mac = true;
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
  std::ifstream in(std::string(GSEC_TEST_DATA) + "/vectors/hmac.vec");
  std::ostringstream buf;
  buf << in.rdbuf();
  return buf.str();
}

}  /* namespace */

TEST(Hmac, CommittedFileMatchesEveryCase) {
  std::string error;
  std::vector<Case> cases;
  ASSERT_TRUE(parse_file(load_committed(), &cases, &error)) << error;
  ASSERT_GE(cases.size(), 8u);
  for (const Case & item : cases) {
    unsigned char got[GSEC_SHA512_DIGEST_LEN];
    unsigned char streamed[GSEC_SHA512_DIGEST_LEN];
    GSEC_Hmac ctx;
    size_t i;
    SCOPED_TRACE(item.name);
    ASSERT_EQ(gsec_hmac(item.hash,
        item.key.empty() ? nullptr : item.key.data(), item.key.size(),
        item.msg.empty() ? nullptr : item.msg.data(), item.msg.size(), got),
        GSEC_OK);
    EXPECT_EQ(gsec_equal(got, item.mac.data(), item.digest_len), GSEC_OK);
    EXPECT_EQ(gsec_hmac_verify(item.hash,
        item.key.empty() ? nullptr : item.key.data(), item.key.size(),
        item.msg.empty() ? nullptr : item.msg.data(), item.msg.size(),
        item.mac.data(), item.mac.size()), GSEC_OK);

    ASSERT_EQ(gsec_hmac_init(&ctx, item.hash,
        item.key.empty() ? nullptr : item.key.data(), item.key.size()),
        GSEC_OK);
    for (i = 0; i < item.msg.size(); i++) {
      ASSERT_EQ(gsec_hmac_update(&ctx, item.msg.data() + i, 1), GSEC_OK);
    }
    ASSERT_EQ(gsec_hmac_final(&ctx, streamed), GSEC_OK);
    EXPECT_EQ(gsec_equal(got, streamed, item.digest_len), GSEC_OK);
    EXPECT_EQ(gsec_wipe(got, sizeof got), GSEC_OK);
    EXPECT_EQ(gsec_wipe(streamed, sizeof streamed), GSEC_OK);
  }
}

TEST(Hmac, AWrongMacIsMismatchAndAShortMacIsInvalid) {
  static const unsigned char key[3] = {0x6b, 0x65, 0x79};
  static const unsigned char msg[3] = {0x61, 0x62, 0x63};
  unsigned char mac[GSEC_SHA256_DIGEST_LEN];

  ASSERT_EQ(gsec_hmac(GSEC_HMAC_SHA256, key, sizeof key, msg, sizeof msg, mac),
      GSEC_OK);
  mac[GSEC_SHA256_DIGEST_LEN - 1] =
      static_cast<unsigned char>(mac[GSEC_SHA256_DIGEST_LEN - 1] ^ 0x01u);
  EXPECT_EQ(gsec_hmac_verify(GSEC_HMAC_SHA256, key, sizeof key, msg, sizeof msg,
      mac, sizeof mac), GSEC_ERR_MISMATCH);
  EXPECT_EQ(gsec_hmac_verify(GSEC_HMAC_SHA256, key, sizeof key, msg, sizeof msg,
      mac, sizeof mac - 1), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_wipe(mac, sizeof mac), GSEC_OK);
}

TEST(Hmac, ArgumentsAndAFinishedContext) {
  GSEC_Hmac ctx;
  unsigned char mac[GSEC_SHA256_DIGEST_LEN];
  unsigned char zeros[sizeof ctx];
  const unsigned char key = 0x61;
  const unsigned char byte = 0x62;

  EXPECT_EQ(gsec_hmac_init(nullptr, GSEC_HMAC_SHA256, &key, 1), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_hmac_init(&ctx, 0, &key, 1), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_hmac(GSEC_HMAC_SHA256, nullptr, 1, &byte, 1, mac),
      GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_hmac(GSEC_HMAC_SHA256, &key, 1, &byte, 1, nullptr),
      GSEC_ERR_INVALID);

  ASSERT_EQ(gsec_hmac_init(&ctx, GSEC_HMAC_SHA256, &key, 1), GSEC_OK);
  EXPECT_EQ(gsec_hmac_final(&ctx, nullptr), GSEC_ERR_INVALID);
  EXPECT_EQ(ctx.magic, 0x484d4143u);
  ASSERT_EQ(gsec_hmac_final(&ctx, mac), GSEC_OK);
  std::memset(zeros, 0, sizeof zeros);
  EXPECT_EQ(gsec_equal(reinterpret_cast<unsigned char *>(&ctx), zeros,
      sizeof ctx), GSEC_OK);
  EXPECT_EQ(gsec_hmac_update(&ctx, &byte, 1), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_wipe(mac, sizeof mac), GSEC_OK);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
