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
  EXPECT_EQ(gsec_argon2_version(0x12, GSEC_ARGON2_ID, nullptr, 0, salt,
      sizeof salt, nullptr, 0, nullptr, 0, 8, 1, 1, tag, sizeof tag),
      GSEC_ERR_INVALID);
  EXPECT_EQ(tag[0], 0xa5);
}

TEST(Argon2, Version10MatchesTheReference) {
  unsigned char password[32];
  unsigned char salt[16];
  unsigned char secret[8];
  unsigned char ad[12];
  unsigned char tag[32];
  static const unsigned char d[32] = {
    0x96, 0xa9, 0xd4, 0xe5, 0xa1, 0x73, 0x40, 0x92,
    0xc8, 0x5e, 0x29, 0xf4, 0x10, 0xa4, 0x59, 0x14,
    0xa5, 0xdd, 0x1f, 0x5c, 0xbf, 0x08, 0xb2, 0x67,
    0x0d, 0xa6, 0x8a, 0x02, 0x85, 0xab, 0xf3, 0x2b
  };
  static const unsigned char i[32] = {
    0x87, 0xae, 0xed, 0xd6, 0x51, 0x7a, 0xb8, 0x30,
    0xcd, 0x97, 0x65, 0xcd, 0x82, 0x31, 0xab, 0xb2,
    0xe6, 0x47, 0xa5, 0xde, 0xe0, 0x8f, 0x7c, 0x05,
    0xe0, 0x2f, 0xcb, 0x76, 0x33, 0x35, 0xd0, 0xfd
  };
  static const unsigned char id[32] = {
    0xb6, 0x46, 0x15, 0xf0, 0x77, 0x89, 0xb6, 0x6b,
    0x64, 0x5b, 0x67, 0xee, 0x9e, 0xd3, 0xb3, 0x77,
    0xae, 0x35, 0x0b, 0x6b, 0xfc, 0xbb, 0x0f, 0xc9,
    0x51, 0x41, 0xea, 0x8f, 0x32, 0x26, 0x13, 0xc0
  };

  rfc_inputs(password, salt, secret, ad);
  ASSERT_EQ(gsec_argon2_version(GSEC_ARGON2_VERSION_10, GSEC_ARGON2_D,
      password, sizeof password, salt, sizeof salt, secret, sizeof secret, ad,
      sizeof ad, 32, 3, 4, tag, sizeof tag), GSEC_OK);
  EXPECT_EQ(gsec_equal(tag, d, sizeof tag), GSEC_OK);
  ASSERT_EQ(gsec_argon2_version(GSEC_ARGON2_VERSION_10, GSEC_ARGON2_I,
      password, sizeof password, salt, sizeof salt, secret, sizeof secret, ad,
      sizeof ad, 32, 3, 4, tag, sizeof tag), GSEC_OK);
  EXPECT_EQ(gsec_equal(tag, i, sizeof tag), GSEC_OK);
  ASSERT_EQ(gsec_argon2_version(GSEC_ARGON2_VERSION_10, GSEC_ARGON2_ID,
      password, sizeof password, salt, sizeof salt, secret, sizeof secret, ad,
      sizeof ad, 32, 3, 4, tag, sizeof tag), GSEC_OK);
  EXPECT_EQ(gsec_equal(tag, id, sizeof tag), GSEC_OK);
}

TEST(Argon2, PhcString) {
  static const char encoded[] =
      "$argon2id$v=16$m=32,t=2,p=1$c29tZXNhbHQ$YZeVCSbW/OLMPoPUfNenpu8QTQ/gBcc1Gul/Fwe7oWs";
  static const char modern[] =
      "$argon2id$v=19$m=32,t=2,p=1$c29tZXNhbHQ$MREcwFO6CnmcCIQUj9fsncNjHz6M9HbMqVIdTMxRNug";
  static const char omitted[] =
      "$argon2id$m=32,t=2,p=1$c29tZXNhbHQ$YZeVCSbW/OLMPoPUfNenpu8QTQ/gBcc1Gul/Fwe7oWs";
  char out[160];
  size_t n = 0;

  ASSERT_EQ(gsec_argon2_phc(GSEC_ARGON2_VERSION_10, GSEC_ARGON2_ID, "password",
      8, "somesalt", 8, nullptr, 0, nullptr, 0, 32, 2, 1, 32, out, sizeof out,
      &n), GSEC_OK);
  ASSERT_EQ(n, std::strlen(encoded));
  EXPECT_EQ(std::memcmp(out, encoded, n), 0);
  EXPECT_EQ(gsec_argon2_phc_verify(encoded, std::strlen(encoded), "password", 8,
      nullptr, 0, nullptr, 0), GSEC_OK);
  EXPECT_EQ(gsec_argon2_phc_verify(modern, std::strlen(modern), "password", 8,
      nullptr, 0, nullptr, 0), GSEC_OK);
  EXPECT_EQ(gsec_argon2_phc_verify(omitted, std::strlen(omitted), "password", 8,
      nullptr, 0, nullptr, 0), GSEC_OK);
  EXPECT_EQ(gsec_argon2_phc_verify(encoded, std::strlen(encoded), "passworx", 8,
      nullptr, 0, nullptr, 0), GSEC_ERR_MISMATCH);
  EXPECT_EQ(gsec_argon2_phc_verify("nope", 4, "password", 8, nullptr, 0,
      nullptr, 0), GSEC_ERR_CORRUPT);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
