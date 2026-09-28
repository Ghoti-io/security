/**
 * @file
 *
 * bcrypt against the OpenBSD test vectors.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstring>

TEST(Bcrypt, OpenBsd) {
  static const unsigned char stars_pass[4] = {0x55, 0x2a, 0x55, 0x2a};
  static const unsigned char c_salt[16] = {
    0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41,
    0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10
  };
  static const unsigned char stars_hash[24] = {
    0x5c, 0x84, 0x35, 0x0b, 0xdf, 0xba, 0xa9, 0x6a,
    0xc1, 0x6f, 0x61, 0x5a, 0xe7, 0x9f, 0x35, 0xcf,
    0xda, 0xcd, 0x68, 0x2d, 0x36, 0x9f, 0x23, 0x89
  };
  static const unsigned char empty_hash[24] = {
    0xf7, 0x02, 0x36, 0x5c, 0x4d, 0x4a, 0xe1, 0xd5,
    0x3d, 0x97, 0xcd, 0x28, 0xb0, 0xb9, 0x3f, 0x11,
    0xf7, 0x9f, 0xce, 0x44, 0xd5, 0x60, 0xfd, 0xf1
  };
  static const unsigned char high_pass[3] = {0xff, 0xff, 0xa3};
  static const unsigned char high_salt[16] = {
    0x05, 0x03, 0x00, 0x85, 0xd5, 0xed, 0x4c, 0x17,
    0x6b, 0x2a, 0xc3, 0xcb, 0xee, 0x47, 0x29, 0x1c
  };
  static const unsigned char high_hash[24] = {
    0x10, 0x6e, 0xe0, 0x9c, 0x97, 0x1c, 0x43, 0xa1,
    0x9d, 0x8a, 0x25, 0xc5, 0x95, 0xdf, 0x91, 0xdf,
    0xf4, 0xf0, 0x9b, 0x56, 0x54, 0x3b, 0x98, 0x0c
  };
  unsigned char got[24];

  ASSERT_EQ(gsec_bcrypt(stars_pass, sizeof stars_pass, c_salt, sizeof c_salt,
      5, got, sizeof got), GSEC_OK);
  EXPECT_EQ(gsec_equal(got, stars_hash, sizeof got), GSEC_OK);
  ASSERT_EQ(gsec_bcrypt(nullptr, 0, c_salt, sizeof c_salt, 5, got, sizeof got),
      GSEC_OK);
  EXPECT_EQ(gsec_equal(got, empty_hash, sizeof got), GSEC_OK);
  ASSERT_EQ(gsec_bcrypt(high_pass, sizeof high_pass, high_salt,
      sizeof high_salt, 5, got, sizeof got), GSEC_OK);
  EXPECT_EQ(gsec_equal(got, high_hash, sizeof got), GSEC_OK);
}

TEST(Bcrypt, TwoA) {
  static const unsigned char high_pass[3] = {0xff, 0xff, 0xa3};
  static const unsigned char one_high[1] = {0xa3};
  static const unsigned char high_salt[16] = {
    0x05, 0x03, 0x00, 0x85, 0xd5, 0xed, 0x4c, 0x17,
    0x6b, 0x2a, 0xc3, 0xcb, 0xee, 0x47, 0x29, 0x1c
  };
  static const unsigned char two_b[24] = {
    0x10, 0x6e, 0xe0, 0x9c, 0x97, 0x1c, 0x43, 0xa1,
    0x9d, 0x8a, 0x25, 0xc5, 0x95, 0xdf, 0x91, 0xdf,
    0xf4, 0xf0, 0x9b, 0x56, 0x54, 0x3b, 0x98, 0x0c
  };
  static const unsigned char two_a[24] = {
    0xa6, 0xc7, 0xf7, 0xcb, 0x40, 0x2b, 0x54, 0xe7,
    0xde, 0xc6, 0xd4, 0xd8, 0xcf, 0x49, 0x08, 0x37,
    0x88, 0x0e, 0xd4, 0x0e, 0x1c, 0xfb, 0xb0, 0x46
  };
  static const unsigned char stars_pass[4] = {0x55, 0x2a, 0x55, 0x2a};
  static const unsigned char c_salt[16] = {
    0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41,
    0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10
  };
  unsigned char got[24];
  unsigned char other[24];

  ASSERT_EQ(gsec_bcrypt_2a(high_pass, sizeof high_pass, high_salt,
      sizeof high_salt, 5, got, sizeof got), GSEC_OK);
  EXPECT_EQ(gsec_equal(got, two_a, sizeof got), GSEC_OK);
  EXPECT_EQ(gsec_equal(got, two_b, sizeof got), GSEC_ERR_MISMATCH);
  ASSERT_EQ(gsec_bcrypt_2a(one_high, sizeof one_high, high_salt,
      sizeof high_salt, 5, got, sizeof got), GSEC_OK);
  ASSERT_EQ(gsec_bcrypt(one_high, sizeof one_high, high_salt,
      sizeof high_salt, 5, other, sizeof other), GSEC_OK);
  EXPECT_EQ(gsec_equal(got, other, sizeof got), GSEC_OK);
  ASSERT_EQ(gsec_bcrypt_2a(stars_pass, sizeof stars_pass, c_salt,
      sizeof c_salt, 5, got, sizeof got), GSEC_OK);
  ASSERT_EQ(gsec_bcrypt(stars_pass, sizeof stars_pass, c_salt,
      sizeof c_salt, 5, other, sizeof other), GSEC_OK);
  EXPECT_EQ(gsec_equal(got, other, sizeof got), GSEC_OK);
}

TEST(Bcrypt, RejectsABadCall) {
  unsigned char salt[16];
  unsigned char hash[24];
  unsigned char password[73];
  unsigned i;

  for (i = 0; i < sizeof password; i++) {
    password[i] = 0x61;
  }

  for (i = 0; i < sizeof salt; i++) {
    salt[i] = 1;
  }
  hash[0] = 0xa5;
  EXPECT_EQ(gsec_bcrypt(password, 73, salt, sizeof salt, 4, hash, sizeof hash),
      GSEC_ERR_INVALID);
  EXPECT_EQ(hash[0], 0xa5);
  EXPECT_EQ(gsec_bcrypt_2a(password, 73, salt, sizeof salt, 4, hash, sizeof hash),
      GSEC_ERR_INVALID);
  EXPECT_EQ(hash[0], 0xa5);
  EXPECT_EQ(gsec_bcrypt(nullptr, 0, salt, sizeof salt, 3, hash, sizeof hash),
      GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_bcrypt(nullptr, 1, salt, sizeof salt, 4, hash, sizeof hash),
      GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_bcrypt(nullptr, 0, nullptr, sizeof salt, 4, hash, sizeof hash),
      GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_bcrypt(nullptr, 0, salt, 15, 4, hash, sizeof hash),
      GSEC_ERR_INVALID);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
