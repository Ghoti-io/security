/**
 * @file
 *
 * Argon2 against RFC 9106.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstring>

static void rfc_inputs(unsigned char password[32], unsigned char salt[16],
    unsigned char secret[8], unsigned char ad[12]) {
  unsigned i;

  for (i = 0; i < 32; i++) {
    password[i] = 0x01;
  }
  for (i = 0; i < 16; i++) {
    salt[i] = 0x02;
  }
  for (i = 0; i < 8; i++) {
    secret[i] = 0x03;
  }
  for (i = 0; i < 12; i++) {
    ad[i] = 0x04;
  }
}

TEST(Argon2, Rfc9106) {
  unsigned char password[32];
  unsigned char salt[16];
  unsigned char secret[8];
  unsigned char ad[12];
  unsigned char tag[32];
  static const unsigned char d[32] = {
    0x51, 0x2b, 0x39, 0x1b, 0x6f, 0x11, 0x62, 0x97,
    0x53, 0x71, 0xd3, 0x09, 0x19, 0x73, 0x42, 0x94,
    0xf8, 0x68, 0xe3, 0xbe, 0x39, 0x84, 0xf3, 0xc1,
    0xa1, 0x3a, 0x4d, 0xb9, 0xfa, 0xbe, 0x4a, 0xcb
  };
  static const unsigned char i[32] = {
    0xc8, 0x14, 0xd9, 0xd1, 0xdc, 0x7f, 0x37, 0xaa,
    0x13, 0xf0, 0xd7, 0x7f, 0x24, 0x94, 0xbd, 0xa1,
    0xc8, 0xde, 0x6b, 0x01, 0x6d, 0xd3, 0x88, 0xd2,
    0x99, 0x52, 0xa4, 0xc4, 0x67, 0x2b, 0x6c, 0xe8
  };
  static const unsigned char id[32] = {
    0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c,
    0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
    0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e,
    0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59
  };

  rfc_inputs(password, salt, secret, ad);
  ASSERT_EQ(gsec_argon2(GSEC_ARGON2_D, password, sizeof password, salt,
      sizeof salt, secret, sizeof secret, ad, sizeof ad, 32, 3, 4, tag,
      sizeof tag), GSEC_OK);
  EXPECT_EQ(gsec_equal(tag, d, sizeof tag), GSEC_OK);
  ASSERT_EQ(gsec_argon2(GSEC_ARGON2_I, password, sizeof password, salt,
      sizeof salt, secret, sizeof secret, ad, sizeof ad, 32, 3, 4, tag,
      sizeof tag), GSEC_OK);
  EXPECT_EQ(gsec_equal(tag, i, sizeof tag), GSEC_OK);
  ASSERT_EQ(gsec_argon2(GSEC_ARGON2_ID, password, sizeof password, salt,
      sizeof salt, secret, sizeof secret, ad, sizeof ad, 32, 3, 4, tag,
      sizeof tag), GSEC_OK);
  EXPECT_EQ(gsec_equal(tag, id, sizeof tag), GSEC_OK);
}

TEST(Argon2, RejectsABadCall) {
  unsigned char salt[8];
  unsigned char tag[4];
  unsigned i;

  for (i = 0; i < sizeof salt; i++) {
    salt[i] = 1;
  }
  tag[0] = 0xa5;
  EXPECT_EQ(gsec_argon2(3, nullptr, 0, salt, sizeof salt, nullptr, 0, nullptr,
      0, 8, 1, 1, tag, sizeof tag), GSEC_ERR_INVALID);
  EXPECT_EQ(tag[0], 0xa5);
  EXPECT_EQ(gsec_argon2(GSEC_ARGON2_ID, nullptr, 0, salt, 7, nullptr, 0,
      nullptr, 0, 8, 1, 1, tag, sizeof tag), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_argon2(GSEC_ARGON2_ID, nullptr, 0, salt, sizeof salt, nullptr,
      0, nullptr, 0, 7, 1, 1, tag, sizeof tag), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_argon2(GSEC_ARGON2_ID, nullptr, 0, salt, sizeof salt, nullptr,
      0, nullptr, 0, GSEC_ARGON2_MEMORY_MAX + 1u, 1, 1, tag, sizeof tag),
      GSEC_ERR_LIMIT);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
