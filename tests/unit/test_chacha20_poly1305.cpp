/**
 * @file
 *
 * ChaCha20-Poly1305 against the RFC 8439 vector.
 *
 * A tag that does not match wipes the plaintext. In-place is the same
 * function. An empty message is a tag over the additional data alone.
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
  std::vector<unsigned char> nonce;
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
    if (current.name.empty() || saw != 6 ||
        current.key.size() != GSEC_CHACHA20_KEY_LEN ||
        current.nonce.size() != GSEC_CHACHA20_NONCE_LEN ||
        current.pt.size() != current.ct.size() ||
        current.tag.size() != GSEC_POLY1305_TAG_LEN) {
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
      if (saw_primitive || value != "chacha20-poly1305") {
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
    } else if (key == "nonce") {
      dest = &current.nonce;
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
  std::ifstream in(std::string(GSEC_TEST_DATA) + "/vectors/chacha20_poly1305.vec");
  std::ostringstream buf;
  buf << in.rdbuf();
  return buf.str();
}

const unsigned char * or_null(const std::vector<unsigned char> & bytes) {
  return bytes.empty() ? nullptr : bytes.data();
}

}  /* namespace */

TEST(ChaCha20Poly1305, CommittedFileMatchesEncryptAndDecrypt) {
  std::string error;
  std::vector<Case> cases;
  ASSERT_TRUE(parse_file(load_committed(), &cases, &error)) << error;
  ASSERT_FALSE(cases.empty());
  for (const Case & item : cases) {
    std::vector<unsigned char> ct(item.pt.size());
    std::vector<unsigned char> inplace(item.pt);
    std::vector<unsigned char> back(item.pt.size());
    unsigned char tag[GSEC_POLY1305_TAG_LEN];
    SCOPED_TRACE(item.name);
    ASSERT_EQ(gsec_chacha20_poly1305_encrypt(item.key.data(), item.nonce.data(),
        or_null(item.aad), item.aad.size(), item.pt.data(), item.pt.size(),
        ct.data(), tag), GSEC_OK);
    EXPECT_EQ(gsec_equal(ct.data(), item.ct.data(), item.ct.size()), GSEC_OK);
    EXPECT_EQ(gsec_equal(tag, item.tag.data(), sizeof tag), GSEC_OK);
    ASSERT_EQ(gsec_chacha20_poly1305_decrypt(item.key.data(), item.nonce.data(),
        or_null(item.aad), item.aad.size(), item.ct.data(), item.ct.size(),
        back.data(), item.tag.data()), GSEC_OK);
    EXPECT_EQ(gsec_equal(back.data(), item.pt.data(), item.pt.size()), GSEC_OK);

    ASSERT_EQ(gsec_chacha20_poly1305_encrypt(item.key.data(), item.nonce.data(),
        or_null(item.aad), item.aad.size(), inplace.data(), inplace.size(),
        inplace.data(), tag), GSEC_OK);
    EXPECT_EQ(gsec_equal(inplace.data(), item.ct.data(), item.ct.size()), GSEC_OK);
    ASSERT_EQ(gsec_chacha20_poly1305_decrypt(item.key.data(), item.nonce.data(),
        or_null(item.aad), item.aad.size(), inplace.data(), inplace.size(),
        inplace.data(), tag), GSEC_OK);
    EXPECT_EQ(gsec_equal(inplace.data(), item.pt.data(), item.pt.size()),
        GSEC_OK);
  }
}

TEST(ChaCha20Poly1305, ABadFileIsNotASkippedCase) {
  std::string error;
  std::vector<Case> cases;
  EXPECT_FALSE(parse_file("primitive chacha20-poly1305\ncase x\nnonce zz\n",
      &cases, &error));
  EXPECT_TRUE(cases.empty());
}

TEST(ChaCha20Poly1305, AWrongTagWipesAndEmptyIsATag) {
  unsigned char key[GSEC_CHACHA20_KEY_LEN];
  unsigned char nonce[GSEC_CHACHA20_NONCE_LEN];
  unsigned char pt[8];
  unsigned char ct[8];
  unsigned char back[8];
  unsigned char tag[GSEC_POLY1305_TAG_LEN];
  unsigned char tag2[GSEC_POLY1305_TAG_LEN];
  size_t i;

  for (i = 0; i < sizeof key; i++) {
    key[i] = static_cast<unsigned char>(i);
  }
  for (i = 0; i < sizeof nonce; i++) {
    nonce[i] = 0;
  }
  for (i = 0; i < sizeof pt; i++) {
    pt[i] = static_cast<unsigned char>(i + 1);
  }
  ASSERT_EQ(gsec_chacha20_poly1305_encrypt(key, nonce, nullptr, 0, pt,
      sizeof pt, ct, tag), GSEC_OK);
  tag[0] = static_cast<unsigned char>(tag[0] ^ 1u);
  std::memset(back, 0xa5, sizeof back);
  EXPECT_EQ(gsec_chacha20_poly1305_decrypt(key, nonce, nullptr, 0, ct,
      sizeof ct, back, tag), GSEC_ERR_MISMATCH);
  for (i = 0; i < sizeof back; i++) {
    EXPECT_EQ(back[i], 0);
  }

  ASSERT_EQ(gsec_chacha20_poly1305_encrypt(key, nonce, pt, sizeof pt, nullptr,
      0, nullptr, tag2), GSEC_OK);
  EXPECT_EQ(gsec_chacha20_poly1305_decrypt(key, nonce, pt, sizeof pt, nullptr,
      0, nullptr, tag2), GSEC_OK);
  EXPECT_EQ(gsec_chacha20_poly1305_encrypt(nullptr, nonce, nullptr, 0, pt,
      sizeof pt, ct, tag), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_chacha20_poly1305_encrypt(key, nonce, nullptr, 0, pt,
      sizeof pt, pt + 4, tag), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_wipe(ct, sizeof ct), GSEC_OK);
  EXPECT_EQ(gsec_wipe(tag, sizeof tag), GSEC_OK);
  EXPECT_EQ(gsec_wipe(tag2, sizeof tag2), GSEC_OK);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
