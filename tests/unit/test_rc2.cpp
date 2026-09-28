/**
 * @file
 *
 * RC2 against RFC 2268.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstring>

namespace {

struct Vec {
  const char * key;
  uint32_t effective;
  const char * pt;
  const char * ct;
};

int nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  return -1;
}

void unhex(const char * text, unsigned char * out, size_t * n) {
  size_t len = std::strlen(text);
  size_t i;
  *n = len / 2u;
  for (i = 0; i < *n; i++) {
    out[i] = static_cast<unsigned char>(
        (nibble(text[i * 2u]) << 4) | nibble(text[i * 2u + 1u]));
  }
}

} /* namespace */

TEST(Rc2, Rfc2268) {
  static const Vec cases[] = {
    {"0000000000000000", 63, "0000000000000000", "ebb773f993278eff"},
    {"ffffffffffffffff", 64, "ffffffffffffffff", "278b27e42e2f0d49"},
    {"3000000000000000", 64, "1000000000000001", "30649edf9be7d2c2"},
    {"88", 64, "0000000000000000", "61a8a244adacccf0"},
    {"88bca90e90875a", 64, "0000000000000000", "6ccf4308974c267f"},
    {"88bca90e90875a7f0f79c384627bafb2", 64, "0000000000000000",
        "1a807d272bbe5db1"},
    {"88bca90e90875a7f0f79c384627bafb2", 128, "0000000000000000",
        "2269552ab0f85ca6"},
  };
  size_t i;

  for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
    unsigned char key[16];
    unsigned char pt[8];
    unsigned char ct[8];
    unsigned char got[8];
    unsigned char back[8];
    size_t key_len = 0;
    size_t pt_len = 0;
    size_t ct_len = 0;
    unhex(cases[i].key, key, &key_len);
    unhex(cases[i].pt, pt, &pt_len);
    unhex(cases[i].ct, ct, &ct_len);
    ASSERT_EQ(pt_len, 8u);
    ASSERT_EQ(ct_len, 8u);
    ASSERT_EQ(gsec_rc2_encrypt(key, key_len, cases[i].effective, pt, got),
        GSEC_OK);
    EXPECT_EQ(gsec_equal(got, ct, 8), GSEC_OK);
    ASSERT_EQ(gsec_rc2_decrypt(key, key_len, cases[i].effective, ct, back),
        GSEC_OK);
    EXPECT_EQ(gsec_equal(back, pt, 8), GSEC_OK);
  }
}

TEST(Rc2, RejectsABadCall) {
  unsigned char key[1] = {1};
  unsigned char block[8];
  unsigned char out[8];

  std::memset(block, 2, sizeof block);
  out[0] = 0xa5;
  EXPECT_EQ(gsec_rc2_encrypt(nullptr, 1, 64, block, out), GSEC_ERR_INVALID);
  EXPECT_EQ(out[0], 0xa5);
  EXPECT_EQ(gsec_rc2_encrypt(key, 0, 64, block, out), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_rc2_encrypt(key, 1, 0, block, out), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_rc2_cbc_encrypt(key, 1, 64, block, nullptr, 0, nullptr),
      GSEC_OK);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
