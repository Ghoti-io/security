/**
 * @file
 *
 * AES-GCM against the committed file.
 *
 * A tag that does not match wipes the plaintext. A 12-byte tag is the
 * leading bytes of the 16-byte tag. An empty nonce is rejected.
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
  std::vector<unsigned char> aad;
  std::vector<unsigned char> pt;
  std::vector<unsigned char> ct;
  std::vector<unsigned char> tag;
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
    if (current.name.empty() || saw != 6 || !key_len_ok(current.key.size()) ||
        current.iv.empty() || current.pt.size() != current.ct.size() ||
        current.tag.size() != 16) {
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
      if (saw_primitive || value != "aes-gcm") {
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
    if (key == "key") {
      dest = &current.key;
    } else if (key == "iv") {
      dest = &current.iv;
    } else if (key == "aad") {
      dest = &current.aad;
    } else if (key == "pt") {
      dest = &current.pt;
    } else if (key == "ct") {
      dest = &current.ct;
    } else if (key == "tag") {
      dest = &current.tag;
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
  std::ifstream in(std::string(GSEC_TEST_DATA) + "/vectors/aes_gcm.vec");
  std::ostringstream buf;
  buf << in.rdbuf();
  return buf.str();
}

const unsigned char * or_null(const std::vector<unsigned char> & bytes) {
  return bytes.empty() ? nullptr : bytes.data();
}

}  /* namespace */

TEST(AesGcm, CommittedFileMatchesEncryptAndDecrypt) {
  std::string error;
  std::vector<Case> cases;
  ASSERT_TRUE(parse_file(load_committed(), &cases, &error)) << error;
  ASSERT_GE(cases.size(), 4u);
  for (const Case & item : cases) {
    std::vector<unsigned char> ct(item.pt.size() == 0 ? 1 : item.pt.size());
    std::vector<unsigned char> back(item.pt.size() == 0 ? 1 : item.pt.size());
    unsigned char tag[16];
    SCOPED_TRACE(item.name);
    ASSERT_EQ(gsec_aes_gcm_encrypt(item.key.data(), item.key.size(),
        item.iv.data(), item.iv.size(), or_null(item.aad), item.aad.size(),
        or_null(item.pt), item.pt.size(),
        item.pt.empty() ? nullptr : ct.data(), tag, sizeof tag), GSEC_OK);
    if (!item.ct.empty()) {
      EXPECT_EQ(gsec_equal(ct.data(), item.ct.data(), item.ct.size()), GSEC_OK);
    }
    EXPECT_EQ(gsec_equal(tag, item.tag.data(), sizeof tag), GSEC_OK);
    ASSERT_EQ(gsec_aes_gcm_decrypt(item.key.data(), item.key.size(),
        item.iv.data(), item.iv.size(), or_null(item.aad), item.aad.size(),
        or_null(item.ct), item.ct.size(),
        item.pt.empty() ? nullptr : back.data(), item.tag.data(),
        item.tag.size()), GSEC_OK);
    if (!item.pt.empty()) {
      EXPECT_EQ(gsec_equal(back.data(), item.pt.data(), item.pt.size()),
          GSEC_OK);
    }
  }
}

TEST(AesGcm, ABadFileIsNotASkippedCase) {
  std::string error;
  std::vector<Case> cases;
  EXPECT_FALSE(parse_file("primitive aes-gcm\ncase x\niv zz\n", &cases, &error));
  EXPECT_TRUE(cases.empty());
}

TEST(AesGcm, AShortTagMatchesAndAWrongTagWipes) {
  const unsigned char key[16] = {0};
  const unsigned char iv[12] = {0};
  unsigned char pt[16];
  unsigned char ct[16];
  unsigned char back[16];
  unsigned char tag[16];
  unsigned char short_tag[12];
  size_t i;

  for (i = 0; i < sizeof pt; i++) {
    pt[i] = static_cast<unsigned char>(i + 1);
  }
  ASSERT_EQ(gsec_aes_gcm_encrypt(key, sizeof key, iv, sizeof iv, nullptr, 0,
      pt, sizeof pt, ct, tag, sizeof tag), GSEC_OK);
  for (i = 0; i < sizeof short_tag; i++) {
    short_tag[i] = tag[i];
  }
  std::memset(back, 0xa5, sizeof back);
  ASSERT_EQ(gsec_aes_gcm_decrypt(key, sizeof key, iv, sizeof iv, nullptr, 0,
      ct, sizeof ct, back, short_tag, sizeof short_tag), GSEC_OK);
  EXPECT_EQ(gsec_equal(back, pt, sizeof pt), GSEC_OK);

  tag[15] = static_cast<unsigned char>(tag[15] ^ 1u);
  std::memset(back, 0xa5, sizeof back);
  EXPECT_EQ(gsec_aes_gcm_decrypt(key, sizeof key, iv, sizeof iv, nullptr, 0,
      ct, sizeof ct, back, tag, sizeof tag), GSEC_ERR_MISMATCH);
  for (i = 0; i < sizeof back; i++) {
    EXPECT_EQ(back[i], 0);
  }

  EXPECT_EQ(gsec_aes_gcm_encrypt(key, sizeof key, iv, 0, nullptr, 0, pt,
      sizeof pt, ct, tag, sizeof tag), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_aes_gcm_encrypt(key, sizeof key, iv, sizeof iv, nullptr, 0, pt,
      sizeof pt, ct, tag, 7), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_aes_gcm_encrypt(key, sizeof key, iv, sizeof iv, nullptr, 0, pt,
      sizeof pt, pt + 8, tag, sizeof tag), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_wipe(ct, sizeof ct), GSEC_OK);
  EXPECT_EQ(gsec_wipe(tag, sizeof tag), GSEC_OK);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
