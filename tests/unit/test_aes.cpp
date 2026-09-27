/**
 * @file
 *
 * AES against the committed file, and the contract around the schedule.
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
  std::vector<unsigned char> key;
  std::vector<unsigned char> pt;
  std::vector<unsigned char> ct;
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

bool key_len_ok(size_t n) {
  return n == GSEC_AES128_KEY_LEN || n == GSEC_AES192_KEY_LEN ||
      n == GSEC_AES256_KEY_LEN;
}

bool parse_file(const std::string & text, std::vector<Case> * cases,
    std::string * error) {
  cases->clear();
  std::istringstream in(text);
  std::string line;
  bool saw_primitive = false;
  Case current;
  bool in_case = false;
  bool saw_key = false;
  bool saw_pt = false;
  bool saw_ct = false;

  auto finish = [&]() -> bool {
    if (!in_case) {
      return true;
    }
    if (current.name.empty() || !saw_key || !saw_pt || !saw_ct) {
      *error = "truncated case " + current.name;
      return false;
    }
    if (!key_len_ok(current.key.size()) ||
        current.pt.size() != GSEC_AES_BLOCK_LEN ||
        current.ct.size() != GSEC_AES_BLOCK_LEN) {
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
      if (saw_primitive || value != "aes") {
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
      saw_key = false;
      saw_pt = false;
      saw_ct = false;
      continue;
    }
    if (!in_case || value.empty()) {
      *error = "orphan field";
      return false;
    }
    if (key == "key") {
      if (saw_key || !parse_hex(value, &current.key)) {
        *error = "key in " + current.name;
        return false;
      }
      saw_key = true;
      continue;
    }
    if (key == "pt") {
      if (saw_pt || !parse_hex(value, &current.pt)) {
        *error = "pt in " + current.name;
        return false;
      }
      saw_pt = true;
      continue;
    }
    if (key == "ct") {
      if (saw_ct || !parse_hex(value, &current.ct)) {
        *error = "ct in " + current.name;
        return false;
      }
      saw_ct = true;
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
  std::ifstream in(std::string(GSEC_TEST_DATA) + "/vectors/aes.vec");
  std::ostringstream buf;
  buf << in.rdbuf();
  return buf.str();
}

}  /* namespace */

TEST(Aes, CommittedFileMatchesEncryptAndDecrypt) {
  std::string error;
  std::vector<Case> cases;
  ASSERT_TRUE(parse_file(load_committed(), &cases, &error)) << error;
  ASSERT_GE(cases.size(), 3u);
  for (const Case & item : cases) {
    unsigned char ct[GSEC_AES_BLOCK_LEN];
    unsigned char pt[GSEC_AES_BLOCK_LEN];
    GSEC_Aes ctx;
    SCOPED_TRACE(item.name);
    ASSERT_EQ(gsec_aes_encrypt(item.key.data(), item.key.size(),
        item.pt.data(), ct), GSEC_OK);
    EXPECT_EQ(gsec_equal(ct, item.ct.data(), sizeof ct), GSEC_OK);
    ASSERT_EQ(gsec_aes_decrypt(item.key.data(), item.key.size(),
        item.ct.data(), pt), GSEC_OK);
    EXPECT_EQ(gsec_equal(pt, item.pt.data(), sizeof pt), GSEC_OK);

    ASSERT_EQ(gsec_aes_encrypt_init(&ctx, item.key.data(), item.key.size()),
        GSEC_OK);
    ASSERT_EQ(gsec_aes_encrypt_block(&ctx, item.pt.data(), ct), GSEC_OK);
    EXPECT_EQ(gsec_equal(ct, item.ct.data(), sizeof ct), GSEC_OK);
    ASSERT_EQ(gsec_aes_decrypt_block(&ctx, ct, pt), GSEC_OK);
    EXPECT_EQ(gsec_equal(pt, item.pt.data(), sizeof pt), GSEC_OK);
    EXPECT_EQ(gsec_aes_encrypt_wipe(&ctx), GSEC_OK);
    EXPECT_EQ(gsec_wipe(ct, sizeof ct), GSEC_OK);
    EXPECT_EQ(gsec_wipe(pt, sizeof pt), GSEC_OK);
  }
}

TEST(Aes, ABadFileIsNotASkippedCase) {
  std::string error;
  std::vector<Case> cases;
  EXPECT_FALSE(parse_file("primitive aes\ncase short\nkey 00\npt 00\nct 00\n",
      &cases, &error));
  EXPECT_TRUE(cases.empty());
}

TEST(Aes, ArgumentsInPlaceAndAWipedSchedule) {
  GSEC_Aes ctx;
  unsigned char block[GSEC_AES_BLOCK_LEN];
  unsigned char out[GSEC_AES_BLOCK_LEN];
  unsigned char zeros[sizeof ctx];
  const unsigned char key[GSEC_AES128_KEY_LEN] = {0};

  std::memset(block, 0x11, sizeof block);
  EXPECT_EQ(gsec_aes_encrypt_init(nullptr, key, sizeof key), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_aes_encrypt_init(&ctx, nullptr, sizeof key), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_aes_encrypt(key, 15, block, out), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_aes_encrypt(nullptr, sizeof key, block, out), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_aes_encrypt(key, sizeof key, nullptr, out), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_aes_encrypt(key, sizeof key, block, nullptr), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_aes_encrypt_wipe(nullptr), GSEC_ERR_INVALID);

  ASSERT_EQ(gsec_aes_encrypt_init(&ctx, key, sizeof key), GSEC_OK);
  EXPECT_EQ(ctx.magic, 0x41455331u);
  EXPECT_EQ(ctx.nrounds, 10u);
  EXPECT_EQ(gsec_aes_encrypt_block(&ctx, nullptr, out), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_aes_encrypt_block(nullptr, block, out), GSEC_ERR_INVALID);
  ASSERT_EQ(gsec_aes_encrypt_block(&ctx, block, block), GSEC_OK);
  ASSERT_EQ(gsec_aes_decrypt_block(&ctx, block, block), GSEC_OK);
  std::memset(out, 0x11, sizeof out);
  EXPECT_EQ(gsec_equal(block, out, sizeof block), GSEC_OK);
  EXPECT_EQ(gsec_aes_encrypt_wipe(&ctx), GSEC_OK);
  std::memset(zeros, 0, sizeof zeros);
  EXPECT_EQ(gsec_equal(reinterpret_cast<unsigned char *>(&ctx), zeros,
      sizeof ctx), GSEC_OK);
  EXPECT_EQ(gsec_aes_encrypt_block(&ctx, block, out), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_wipe(block, sizeof block), GSEC_OK);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
