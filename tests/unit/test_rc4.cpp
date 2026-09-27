/**
 * @file
 *
 * RC4 against an OpenSSL known answer.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstring>

TEST(Rc4, OpenSslHello) {
  static const unsigned char key[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
  static const unsigned char pt[5] = {0x68, 0x65, 0x6c, 0x6c, 0x6f};
  static const unsigned char ct[5] = {0xda, 0x5c, 0x0f, 0x69, 0x9f};
  unsigned char got[5];
  unsigned char back[5];

  ASSERT_EQ(gsec_rc4(key, sizeof key, pt, sizeof pt, got), GSEC_OK);
  EXPECT_EQ(gsec_equal(got, ct, sizeof ct), GSEC_OK);
  ASSERT_EQ(gsec_rc4(key, sizeof key, got, sizeof got, back), GSEC_OK);
  EXPECT_EQ(gsec_equal(back, pt, sizeof pt), GSEC_OK);
  ASSERT_EQ(gsec_rc4(key, sizeof key, pt, sizeof pt, got), GSEC_OK);
  EXPECT_EQ(gsec_equal(got, ct, sizeof ct), GSEC_OK);

  static const unsigned char key2[3] = {0x4b, 0x65, 0x79};
  static const unsigned char pt2[9] = {
    0x50, 0x6c, 0x61, 0x69, 0x6e, 0x74, 0x65, 0x78, 0x74
  };
  static const unsigned char ct2[9] = {
    0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3
  };
  unsigned char got2[9];
  ASSERT_EQ(gsec_rc4(key2, sizeof key2, pt2, sizeof pt2, got2), GSEC_OK);
  EXPECT_EQ(gsec_equal(got2, ct2, sizeof ct2), GSEC_OK);
}

TEST(Rc4, RejectsABadCall) {
  unsigned char key[1] = {1};
  unsigned char block[2] = {2, 3};
  unsigned char out[2];

  out[0] = 0xa5;
  EXPECT_EQ(gsec_rc4(nullptr, 1, block, 2, out), GSEC_ERR_INVALID);
  EXPECT_EQ(out[0], 0xa5);
  EXPECT_EQ(gsec_rc4(key, 0, block, 2, out), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_rc4(key, 257, block, 2, out), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_rc4(key, 1, nullptr, 0, nullptr), GSEC_OK);
  EXPECT_EQ(gsec_rc4(key, 1, block, 2, block + 1), GSEC_ERR_INVALID);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
