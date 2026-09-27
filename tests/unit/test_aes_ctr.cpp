/**
 * @file
 *
 * AES-CTR against the committed file, both counter directions.
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
  uint32_t direction;
  std::vector<unsigned char> key;
  std::vector<unsigned char> counter;
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
  int saw = 0;

  auto finish = [&]() -> bool {
    if (!in_case) {
      return true;
    }
    if (current.name.empty() || saw != 5 || !key_len_ok(current.key.size()) ||
        current.counter.size() != GSEC_AES_BLOCK_LEN ||
        current.pt.size() != current.ct.size()) {
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
      if (saw_primitive || value != "aes-ctr") {
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
    if (key == "direction") {
      if (value == "be") {
        current.direction = GSEC_AES_CTR_BE;
      } else if (value == "le") {
        current.direction = GSEC_AES_CTR_LE;
      } else {
        *error = "direction";
        return false;
      }
      saw++;
      continue;
    }
    std::vector<unsigned char> * dest = nullptr;
    if (key == "key") {
      dest = &current.key;
    } else if (key == "counter") {
      dest = &current.counter;
    } else if (key == "pt") {
      dest = &current.pt;
    } else if (key == "ct") {
      dest = &current.ct;
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
  std::ifstream in(std::string(GSEC_TEST_DATA) + "/vectors/aes_ctr.vec");
  std::ostringstream buf;
  buf << in.rdbuf();
  return buf.str();
}

}  /* namespace */

TEST(AesCtr, CommittedFileMatchesOneShotAndSlices) {
  std::string error;
  std::vector<Case> cases;
  ASSERT_TRUE(parse_file(load_committed(), &cases, &error)) << error;
  ASSERT_GE(cases.size(), 4u);
  for (const Case & item : cases) {
    std::vector<unsigned char> got(item.pt.size() == 0 ? 1 : item.pt.size());
    std::vector<unsigned char> sliced(item.pt.size() == 0 ? 1 : item.pt.size());
    GSEC_Aes_Ctr ctx;
    size_t off;
    SCOPED_TRACE(item.name);
    ASSERT_EQ(gsec_aes_ctr(item.key.data(), item.key.size(), item.counter.data(),
        item.direction, item.pt.empty() ? nullptr : item.pt.data(),
        item.pt.empty() ? nullptr : got.data(), item.pt.size()), GSEC_OK);
    if (!item.ct.empty()) {
      EXPECT_EQ(gsec_equal(got.data(), item.ct.data(), item.ct.size()), GSEC_OK);
    }
    ASSERT_EQ(gsec_aes_ctr_init(&ctx, item.key.data(), item.key.size(),
        item.counter.data(), item.direction), GSEC_OK);
    for (off = 0; off < item.pt.size(); off++) {
      ASSERT_EQ(gsec_aes_ctr_update(&ctx, item.pt.data() + off,
          sliced.data() + off, 1), GSEC_OK);
    }
    if (!item.ct.empty()) {
      EXPECT_EQ(gsec_equal(sliced.data(), item.ct.data(), item.ct.size()),
          GSEC_OK);
    }
    EXPECT_EQ(gsec_aes_ctr_wipe(&ctx), GSEC_OK);
  }
}

TEST(AesCtr, ABadFileIsNotASkippedCase) {
  std::string error;
  std::vector<Case> cases;
  EXPECT_FALSE(parse_file("primitive aes-ctr\ncase x\ndirection up\n",
      &cases, &error));
  EXPECT_TRUE(cases.empty());
}

TEST(AesCtr, LittleEndianMatchesTheNextBlockAndOverlapIsInvalid) {
  const unsigned char key[GSEC_AES128_KEY_LEN] = {1, 2, 3, 4};
  unsigned char counter[GSEC_AES_BLOCK_LEN];
  unsigned char pt[20];
  unsigned char ct[20];
  unsigned char block[GSEC_AES_BLOCK_LEN];
  unsigned char ks[GSEC_AES_BLOCK_LEN];
  unsigned char buf[32];
  size_t i;

  std::memset(counter, 0, sizeof counter);
  counter[0] = 1;
  std::memset(pt, 0xa5, sizeof pt);
  ASSERT_EQ(gsec_aes_ctr(key, sizeof key, counter, GSEC_AES_CTR_LE, pt, ct,
      sizeof pt), GSEC_OK);
  ASSERT_EQ(gsec_aes_encrypt(key, sizeof key, counter, ks), GSEC_OK);
  for (i = 0; i < 16; i++) {
    block[i] = static_cast<unsigned char>(pt[i] ^ ks[i]);
  }
  EXPECT_EQ(gsec_equal(ct, block, 16), GSEC_OK);
  counter[0] = 2;
  ASSERT_EQ(gsec_aes_encrypt(key, sizeof key, counter, ks), GSEC_OK);
  for (i = 0; i < 4; i++) {
    block[i] = static_cast<unsigned char>(pt[16 + i] ^ ks[i]);
  }
  EXPECT_EQ(gsec_equal(ct + 16, block, 4), GSEC_OK);

  std::memset(buf, 1, sizeof buf);
  EXPECT_EQ(gsec_aes_ctr(key, sizeof key, counter, GSEC_AES_CTR_BE, buf,
      buf + 8, 16), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_aes_ctr(key, sizeof key, counter, 0, buf, buf, 16),
      GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_aes_ctr(key, 15, counter, GSEC_AES_CTR_BE, buf, buf, 16),
      GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_aes_ctr_wipe(nullptr), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_wipe(ct, sizeof ct), GSEC_OK);
  EXPECT_EQ(gsec_wipe(ks, sizeof ks), GSEC_OK);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
