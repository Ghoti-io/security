/**
 * @file
 *
 * DES and Triple DES against FIPS and OpenSSL known answers.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  return -1;
}

std::vector<unsigned char> hex(const char * text) {
  std::vector<unsigned char> out;
  size_t n = std::strlen(text);
  for (size_t i = 0; i < n; i += 2) {
    out.push_back(static_cast<unsigned char>(
        (hex_value(text[i]) << 4) | hex_value(text[i + 1])));
  }
  return out;
}

}  /* namespace */

TEST(Des, FipsBlockAndOpenSslTriple) {
  auto key = hex("133457799bbcdff1");
  auto pt = hex("0123456789abcdef");
  auto ct = hex("85e813540f0ab405");
  unsigned char got[8];
  unsigned char back[8];

  ASSERT_EQ(gsec_des_encrypt(key.data(), pt.data(), got), GSEC_OK);
  EXPECT_EQ(gsec_equal(got, ct.data(), 8), GSEC_OK);
  ASSERT_EQ(gsec_des_decrypt(key.data(), got, back), GSEC_OK);
  EXPECT_EQ(gsec_equal(back, pt.data(), 8), GSEC_OK);

  auto iv = hex("0000000000000000");
  auto pt2 = hex("0123456789abcdef0123456789abcdef");
  auto ct2 = hex("85e813540f0ab405eb46291166493cd4");
  unsigned char wide[16];
  unsigned char wide_back[16];
  ASSERT_EQ(gsec_des_cbc_encrypt(key.data(), iv.data(), pt2.data(), 16, wide),
      GSEC_OK);
  EXPECT_EQ(gsec_equal(wide, ct2.data(), 16), GSEC_OK);
  ASSERT_EQ(gsec_des_cbc_decrypt(key.data(), iv.data(), wide, 16, wide_back),
      GSEC_OK);
  EXPECT_EQ(gsec_equal(wide_back, pt2.data(), 16), GSEC_OK);

  auto k3 = hex("0123456789abcdef5555555555555555fedcba9876543210");
  auto ct3 = hex("6b9ef97b5c955c29");
  ASSERT_EQ(gsec_des_ede3_encrypt(k3.data(), pt.data(), got), GSEC_OK);
  EXPECT_EQ(gsec_equal(got, ct3.data(), 8), GSEC_OK);
  ASSERT_EQ(gsec_des_ede3_decrypt(k3.data(), got, back), GSEC_OK);
  EXPECT_EQ(gsec_equal(back, pt.data(), 8), GSEC_OK);

  auto k2 = hex("00112233445566778899aabbccddeeff");
  auto iv2 = hex("0102030405060708");
  auto pt16 = hex("6162636465666768696a6b6c6d6e6f70");
  auto ct2k = hex("7c430a32f889c35c1d5e617482b940a0");
  ASSERT_EQ(gsec_des_ede2_cbc_encrypt(k2.data(), iv2.data(), pt16.data(), 16,
      wide), GSEC_OK);
  EXPECT_EQ(gsec_equal(wide, ct2k.data(), 16), GSEC_OK);
  ASSERT_EQ(gsec_des_ede2_cbc_decrypt(k2.data(), iv2.data(), wide, 16,
      wide_back), GSEC_OK);
  EXPECT_EQ(gsec_equal(wide_back, pt16.data(), 16), GSEC_OK);
}

TEST(Des, RejectsABadCall) {
  unsigned char key[8];
  unsigned char block[8];
  unsigned char out[8];

  std::memset(key, 1, sizeof key);
  std::memset(block, 2, sizeof block);
  out[0] = 0xa5;
  EXPECT_EQ(gsec_des_encrypt(nullptr, block, out), GSEC_ERR_INVALID);
  EXPECT_EQ(out[0], 0xa5);
  EXPECT_EQ(gsec_des_cbc_encrypt(key, block, block, 7, out), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_des_cbc_encrypt(key, block, nullptr, 0, nullptr), GSEC_OK);
  EXPECT_EQ(gsec_des_ede3_encrypt(nullptr, block, out), GSEC_ERR_INVALID);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
