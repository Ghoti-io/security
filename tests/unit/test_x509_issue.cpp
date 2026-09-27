/**
 * @file
 *
 * A certificate this library builds and then validates itself.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstdint>
#include <cstring>
#include <vector>

namespace {

const unsigned char kName[] = {
  0x30, 0x0d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03,
  0x0c, 0x02, 0x63, 0x61
};

const int64_t kNotBefore = 1577836800;
const int64_t kNotAfter = 1893456000;
const int64_t kInside = 1600000000;

} /* namespace */

TEST(X509Issue, SelfSignedP256Validates) {
  unsigned char scalar[GSEC_ECDSA_P256_LEN];
  unsigned char point[64];
  unsigned char serial[1] = {0x01};
  unsigned char der[4096];
  size_t n = 0;
  GSEC_X509_Tbs tbs;
  GSEC_X509_Signer signer;
  GSEC_X509 parsed;
  std::memset(scalar, 0, sizeof scalar);
  scalar[sizeof scalar - 1] = 1;
  ASSERT_EQ(gsec_ecdsa_p256_public(scalar, point), GSEC_OK);
  std::memset(&tbs, 0, sizeof tbs);
  std::memset(&signer, 0, sizeof signer);
  tbs.issuer = kName;
  tbs.issuer_len = sizeof kName;
  tbs.subject = kName;
  tbs.subject_len = sizeof kName;
  tbs.not_before = kNotBefore;
  tbs.not_after = kNotAfter;
  tbs.serial = serial;
  tbs.serial_len = 1;
  tbs.subject_key = GSEC_X509_P256;
  tbs.point = point;
  tbs.point_len = sizeof point;
  tbs.ca = 1;
  tbs.dns = "ca.example";
  tbs.dns_len = 10;
  signer.key = GSEC_X509_P256;
  signer.d = scalar;
  signer.d_len = sizeof scalar;
  ASSERT_EQ(gsec_x509_issue(&tbs, &signer, der, sizeof der, &n), GSEC_OK);
  ASSERT_EQ(gsec_x509_parse(der, n, &parsed), GSEC_OK);
  EXPECT_EQ(parsed.key, GSEC_X509_P256);
  EXPECT_EQ(parsed.ca, 1);
  EXPECT_EQ(parsed.dns_san, 1);
  EXPECT_EQ(parsed.not_before, kNotBefore);
  EXPECT_EQ(parsed.not_after, kNotAfter);
  EXPECT_EQ(gsec_x509_signed_by(&parsed, &parsed), GSEC_OK);
  EXPECT_EQ(gsec_x509_path(der, n, nullptr, nullptr, 0, der, n, kInside),
      GSEC_OK);
  EXPECT_EQ(gsec_x509_hostname(&parsed, "ca.example", 10), GSEC_OK);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
