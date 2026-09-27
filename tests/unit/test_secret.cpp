/**
 * @file
 *
 * Constant-time comparison, wiping, and the memcheck marks in a normal build.
 *
 * The proof that comparison does not branch on the secret is `make check-ct`,
 * which rebuilds this file's functions with GSEC_CT_TEST and runs them under
 * memcheck. These tests pin the answers.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstdint>
#include <cstring>
#include <vector>

TEST(Equal, EmptyRegionsAreEqualIncludingNull) {
  EXPECT_EQ(gsec_equal(nullptr, nullptr, 0), GSEC_OK);
  const unsigned char byte = 0;
  EXPECT_EQ(gsec_equal(&byte, nullptr, 0), GSEC_OK);
  EXPECT_EQ(gsec_equal(nullptr, &byte, 0), GSEC_OK);
}

TEST(Equal, NullPointerWithALengthIsInvalid) {
  const unsigned char byte = 0;
  EXPECT_EQ(gsec_equal(nullptr, &byte, 1), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_equal(&byte, nullptr, 1), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_equal(nullptr, nullptr, 1), GSEC_ERR_INVALID);
}

TEST(Equal, IdenticalBytesMatch) {
  const unsigned char a[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
  EXPECT_EQ(gsec_equal(a, a, sizeof a), GSEC_OK);
}

TEST(Equal, ADifferenceAtEitherEndMismatches) {
  unsigned char a[8] = {0, 1, 2, 3, 4, 5, 6, 7};
  unsigned char b[8] = {0, 1, 2, 3, 4, 5, 6, 7};

  b[0] = 0xFF;
  EXPECT_EQ(gsec_equal(a, b, sizeof a), GSEC_ERR_MISMATCH);
  b[0] = 0;
  b[7] = 0xFF;
  EXPECT_EQ(gsec_equal(a, b, sizeof a), GSEC_ERR_MISMATCH);
  b[7] = 7;
  b[3] = 0xFF;
  EXPECT_EQ(gsec_equal(a, b, sizeof a), GSEC_ERR_MISMATCH);
}

TEST(Equal, EverySingleBitDifferenceMismatches) {
  unsigned char a[4] = {0, 0, 0, 0};
  unsigned char b[4] = {0, 0, 0, 0};
  for (size_t i = 0; i < sizeof a; i++) {
    for (int bit = 0; bit < 8; bit++) {
      b[i] = static_cast<unsigned char>(1u << bit);
      EXPECT_EQ(gsec_equal(a, b, sizeof a), GSEC_ERR_MISMATCH)
          << "byte " << i << " bit " << bit;
      b[i] = 0;
    }
  }
  EXPECT_EQ(gsec_equal(a, b, sizeof a), GSEC_OK);
}

TEST(Wipe, OverwritesEveryByte) {
  unsigned char buffer[17];
  std::memset(buffer, 0xA5, sizeof buffer);
  EXPECT_EQ(gsec_wipe(buffer, sizeof buffer), GSEC_OK);
  for (size_t i = 0; i < sizeof buffer; i++) {
    EXPECT_EQ(buffer[i], 0) << i;
  }
}

TEST(Wipe, NullWithALengthIsInvalidAndZeroLengthIsNot) {
  EXPECT_EQ(gsec_wipe(nullptr, 4), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_wipe(nullptr, 0), GSEC_OK);
  unsigned char byte = 0xA5;
  EXPECT_EQ(gsec_wipe(&byte, 0), GSEC_OK);
  EXPECT_EQ(byte, 0xA5);
}

TEST(Wipe, DoesNotWritePastTheRequestedLength) {
  unsigned char buffer[4] = {1, 2, 3, 4};
  EXPECT_EQ(gsec_wipe(buffer, 2), GSEC_OK);
  EXPECT_EQ(buffer[0], 0);
  EXPECT_EQ(buffer[1], 0);
  EXPECT_EQ(buffer[2], 3);
  EXPECT_EQ(buffer[3], 4);
}

TEST(Poison, IsCallableInANormalBuild) {
  unsigned char buffer[4] = {1, 2, 3, 4};
  gsec_poison(nullptr, 4);
  gsec_poison(buffer, 0);
  gsec_poison(buffer, sizeof buffer);
  gsec_unpoison(buffer, sizeof buffer);
  EXPECT_EQ(buffer[0], 1);
  EXPECT_EQ(gsec_equal(buffer, buffer, sizeof buffer), GSEC_OK);
}

TEST(Secret, StackBufferIsNotLeftHoldingThePreimage) {
  /* A function-shaped check: wipe, then the bytes a later reader would see
   * are zeros. This does not prove the compiler kept the wipe — the volatile
   * call in gsec_wipe is what does that — it proves the bytes are zeros when
   * wipe says it wrote them. */
  std::vector<unsigned char> secret(64, 0x5A);
  ASSERT_EQ(gsec_wipe(secret.data(), secret.size()), GSEC_OK);
  for (unsigned char byte : secret) {
    EXPECT_EQ(byte, 0);
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
