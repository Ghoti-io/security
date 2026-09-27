/**
 * @file
 *
 * The result vocabulary, the limits, the version, and the allocator.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/security/libver.h>

#include <set>
#include <string>

/* CONVENTIONS.md section 5: GSEC_RESULT_COUNT closes the enum so a test can
 * check the string table is complete. A new result without a string falls
 * through to "Unknown error" and is caught here. */
TEST(Result, EveryCodeHasItsOwnString) {
  std::set<std::string> seen;
  for (int i = 0; i < GSEC_RESULT_COUNT; i++) {
    const char * s = gsec_result_string(static_cast<GSEC_Result>(i));
    ASSERT_NE(s, nullptr);
    EXPECT_STRNE(s, "Unknown error") << "result " << i;
    EXPECT_TRUE(seen.insert(s).second) << "result " << i << " shares a string";
  }
}

TEST(Result, OutOfRangeIsUnknownNotUndefined) {
  EXPECT_STREQ(gsec_result_string(GSEC_RESULT_COUNT), "Unknown error");
  EXPECT_STREQ(gsec_result_string(static_cast<GSEC_Result>(-1)),
      "Unknown error");
}

TEST(Result, ZeroIsSuccess) {
  EXPECT_EQ(GSEC_OK, 0);
  EXPECT_STREQ(gsec_result_string(GSEC_OK), "No error");
}

TEST(Result, MismatchIsNotInvalid) {
  EXPECT_STRNE(gsec_result_string(GSEC_ERR_MISMATCH),
      gsec_result_string(GSEC_ERR_INVALID));
  EXPECT_STREQ(gsec_result_string(GSEC_ERR_MISMATCH), "Verification failed");
}

TEST(Limits, DefaultCapsRandomAtOneMebibyte) {
  GSEC_Limits limits;
  limits.max_random_bytes = 0;
  gsec_limits_default(&limits);
  EXPECT_EQ(limits.max_random_bytes, static_cast<size_t>(1) << 20);
}

TEST(Limits, NullDefaultIsIgnored) {
  gsec_limits_default(nullptr);
}

TEST(Version, StringMatchesTheGeneratedHeader) {
  EXPECT_STREQ(gsec_version_string(), GSEC_VERSION_STRING);
  EXPECT_EQ(gsec_version_number(), GSEC_VERSION_NUMBER);
  EXPECT_EQ(GSEC_VERSION_NUMBER,
      GSEC_MAKE_VERSION(GSEC_VERSION_MAJOR, GSEC_VERSION_MINOR,
          GSEC_VERSION_PATCH));
}

TEST(Allocator, DefaultIsCutils) {
  const GSEC_Allocator * allocator = gsec_allocator_default();
  ASSERT_NE(allocator, nullptr);
  EXPECT_EQ(allocator, gcu_allocator_default());
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
