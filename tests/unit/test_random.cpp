/**
 * @file
 *
 * The entropy call: fail closed, bounded, and it does write.
 *
 * Two draws are not required to differ. 32 bytes of one fixed sentinel from
 * the kernel is not a plausible "the call forgot to write", which is the
 * failure these tests are about. A collision between two draws is a different
 * question and is not asserted.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <ghoti.io/cutil/random.h>

#include <cstdint>
#include <cstring>
#include <vector>

TEST(Random, ZeroLengthSucceedsAndDoesNotNeedABuffer) {
  EXPECT_EQ(gsec_random_bytes(nullptr, 0, nullptr), GSEC_OK);
  unsigned char byte = 0xA5;
  EXPECT_EQ(gsec_random_bytes(&byte, 0, nullptr), GSEC_OK);
  EXPECT_EQ(byte, 0xA5);
}

TEST(Random, NullBufferIsInvalid) {
  EXPECT_EQ(gsec_random_bytes(nullptr, 16, nullptr), GSEC_ERR_INVALID);
}

TEST(Random, OverwritesASentinel) {
  unsigned char buffer[32];
  std::memset(buffer, 0xA5, sizeof buffer);
  ASSERT_EQ(gsec_random_bytes(buffer, sizeof buffer, nullptr), GSEC_OK);
  unsigned changed = 0;
  for (unsigned char byte : buffer) {
    changed |= static_cast<unsigned>(byte ^ 0xA5);
  }
  EXPECT_NE(changed, 0u);
  EXPECT_EQ(gsec_wipe(buffer, sizeof buffer), GSEC_OK);
}

TEST(Random, DefaultLimitRejectsOneBytePastOneMebibyte) {
  GSEC_Limits limits;
  gsec_limits_default(&limits);
  std::vector<unsigned char> buffer(4, 0xA5);
  /* Ask for more than the cap without allocating it: the cap is checked
   * before the buffer is touched, so a tiny buffer and a huge length must
   * come back ERR_LIMIT with the sentinel intact. */
  EXPECT_EQ(gsec_random_bytes(buffer.data(), limits.max_random_bytes + 1,
                nullptr),
      GSEC_ERR_LIMIT);
  EXPECT_EQ(buffer[0], 0xA5);
  EXPECT_EQ(buffer[3], 0xA5);
}

TEST(Random, ACallerCanRaiseTheCap) {
  GSEC_Limits limits;
  gsec_limits_default(&limits);
  limits.max_random_bytes = 8;
  unsigned char buffer[8];
  std::memset(buffer, 0xA5, sizeof buffer);
  EXPECT_EQ(gsec_random_bytes(buffer, 9, &limits), GSEC_ERR_LIMIT);
  EXPECT_EQ(buffer[0], 0xA5);
  ASSERT_EQ(gsec_random_bytes(buffer, 8, &limits), GSEC_OK);
  EXPECT_EQ(gsec_wipe(buffer, sizeof buffer), GSEC_OK);
}

TEST(Random, AZeroCapRejectsAnyByte) {
  GSEC_Limits limits;
  limits.max_random_bytes = 0;
  unsigned char byte = 0xA5;
  EXPECT_EQ(gsec_random_bytes(&byte, 1, &limits), GSEC_ERR_LIMIT);
  EXPECT_EQ(byte, 0xA5);
  EXPECT_EQ(gsec_random_bytes(&byte, 0, &limits), GSEC_OK);
}

TEST(Random, OpenDrawsThroughTheHandle) {
  GCU_Random * handle = gsec_random_open();
  ASSERT_NE(handle, nullptr);
  unsigned char buffer[32];
  std::memset(buffer, 0xA5, sizeof buffer);
  ASSERT_EQ(gcu_random_bytes(handle, buffer, sizeof buffer), 0);
  unsigned changed = 0;
  for (unsigned char byte : buffer) {
    changed |= static_cast<unsigned>(byte ^ 0xA5);
  }
  EXPECT_NE(changed, 0u);
  uint64_t word = 0;
  EXPECT_EQ(gcu_random_u64(handle, &word), 0);
  EXPECT_EQ(gsec_wipe(buffer, sizeof buffer), GSEC_OK);
  gcu_random_free(handle);
  gcu_random_free(nullptr);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
