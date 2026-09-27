/**
 * @file
 *
 * AES-CBC against the committed file.
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
  std::vector<unsigned char> iv;
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
    if (current.name.empty() || saw != 4 || !key_len_ok(current.key.size()) ||
        current.iv.size() != GSEC_AES_BLOCK_LEN ||
        current.pt.size() != current.ct.size() ||
        (current.pt.size() % GSEC_AES_BLOCK_LEN) != 0) {
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
    if (line.rfind("primitive ", 0) == 0) {
      saw_primitive = line == "primitive aes-cbc";
      continue;
    }
    if (line.rfind("case ", 0) == 0) {
      if (!finish()) {
        return false;
      }
      current = Case();
      current.name = line.substr(5);
      in_case = true;
      saw = 0;
      continue;
    }
    if (line.rfind("bits ", 0) == 0) {
      continue;
    }
    auto space = line.find(' ');
    if (space == std::string::npos || !in_case) {
      *error = line;
      return false;
    }
    std::string key = line.substr(0, space);
    std::string value = line.substr(space + 1);
    std::vector<unsigned char> * dest = nullptr;
    if (key == "key") {
      dest = &current.key;
    } else if (key == "iv") {
      dest = &current.iv;
    } else if (key == "pt") {
      dest = &current.pt;
    } else if (key == "ct") {
      dest = &current.ct;
    } else {
      *error = key;
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
  std::ifstream in(std::string(GSEC_TEST_DATA) + "/vectors/aes_cbc.vec");
  std::ostringstream buf;
  buf << in.rdbuf();
  return buf.str();
}

}  /* namespace */

TEST(AesCbc, CommittedFileRoundTrips) {
  std::string error;
  std::vector<Case> cases;
  ASSERT_TRUE(parse_file(load_committed(), &cases, &error)) << error;
  ASSERT_GE(cases.size(), 3u);
  for (const Case & item : cases) {
    std::vector<unsigned char> got(item.pt.empty() ? 1 : item.pt.size());
    std::vector<unsigned char> back(item.pt.empty() ? 1 : item.pt.size());
    const unsigned char * pt = item.pt.empty() ? nullptr : item.pt.data();
    const unsigned char * ct = item.ct.empty() ? nullptr : item.ct.data();
    unsigned char * enc = item.pt.empty() ? nullptr : got.data();
    unsigned char * dec = item.pt.empty() ? nullptr : back.data();
    SCOPED_TRACE(item.name);
    ASSERT_EQ(gsec_aes_cbc_encrypt(item.key.data(), item.key.size(),
        item.iv.data(), pt, item.pt.size(), enc), GSEC_OK);
    if (!item.ct.empty()) {
      EXPECT_EQ(gsec_equal(got.data(), item.ct.data(), item.ct.size()),
          GSEC_OK);
    }
    ASSERT_EQ(gsec_aes_cbc_decrypt(item.key.data(), item.key.size(),
        item.iv.data(), item.ct.empty() ? enc : ct, item.ct.size(), dec),
        GSEC_OK);
    if (!item.pt.empty()) {
      EXPECT_EQ(gsec_equal(back.data(), item.pt.data(), item.pt.size()),
          GSEC_OK);
    }
  }
}

TEST(AesCbc, RejectsABadCall) {
  unsigned char key[16];
  unsigned char iv[16];
  unsigned char block[16];
  unsigned char out[32];
  unsigned char sentinel = 0xa5;

  std::memset(key, 1, sizeof key);
  std::memset(iv, 2, sizeof iv);
  std::memset(block, 3, sizeof block);
  out[0] = sentinel;
  EXPECT_EQ(gsec_aes_cbc_encrypt(nullptr, 16, iv, block, 16, out),
      GSEC_ERR_INVALID);
  EXPECT_EQ(out[0], sentinel);
  EXPECT_EQ(gsec_aes_cbc_encrypt(key, 15, iv, block, 16, out),
      GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_aes_cbc_encrypt(key, 16, nullptr, block, 16, out),
      GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_aes_cbc_encrypt(key, 16, iv, block, 15, out),
      GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_aes_cbc_encrypt(key, 16, iv, nullptr, 16, out),
      GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_aes_cbc_encrypt(key, 16, iv, block, 16, nullptr),
      GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_aes_cbc_encrypt(key, 16, iv, block, 0, nullptr), GSEC_OK);
  EXPECT_EQ(gsec_aes_cbc_encrypt(key, 16, iv, block, 16, block + 1),
      GSEC_ERR_INVALID);
  ASSERT_EQ(gsec_aes_cbc_encrypt(key, 16, iv, block, 16, out), GSEC_OK);
  ASSERT_EQ(gsec_aes_cbc_decrypt(key, 16, iv, out, 16, out), GSEC_OK);
  EXPECT_EQ(gsec_equal(out, block, 16), GSEC_OK);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
