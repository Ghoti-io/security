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

namespace {

const unsigned char kName[] = {
  0x30, 0x0d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03,
  0x0c, 0x02, 0x63, 0x61
};

/* The 512-bit key from tests/data/vectors/rsa_private.vec. */
const unsigned char kRsaN[] = {
  0xc8, 0x8a, 0xe1, 0x14, 0xb3, 0xe5, 0x6a, 0x6f, 0x5e, 0xc5, 0x24, 0xd3,
  0x3d, 0x15, 0xe5, 0x48, 0xaf, 0x33, 0xb2, 0xcb, 0xc0, 0xcc, 0x0b, 0xaf,
  0x87, 0x2f, 0x53, 0xe5, 0x5a, 0x25, 0x53, 0xb2, 0x26, 0x05, 0xc2, 0x31,
  0x85, 0x8e, 0xe4, 0x73, 0x03, 0xeb, 0xfd, 0x9d, 0x47, 0xe1, 0x8e, 0x1e,
  0x7b, 0x3c, 0xd4, 0x92, 0xe6, 0xd0, 0x9a, 0xc0, 0xd2, 0x73, 0x3a, 0x4a,
  0x45, 0x94, 0x83, 0x21,
};

const unsigned char kRsaE[] = {0x01, 0x00, 0x01};

const unsigned char kRsaD[] = {
  0xaf, 0xa3, 0x22, 0x9a, 0x75, 0x2c, 0x3a, 0x59, 0xac, 0x10, 0xd1, 0xbd,
  0xc8, 0x44, 0x42, 0xf9, 0xb3, 0xa8, 0x7d, 0xb1, 0x81, 0xfb, 0xb3, 0x48,
  0x5a, 0x07, 0x93, 0x5c, 0xcd, 0xe4, 0xdf, 0x35, 0x1a, 0xb5, 0x1b, 0xb6,
  0x93, 0x92, 0x59, 0x2b, 0xa0, 0x32, 0xf1, 0x36, 0xd3, 0x98, 0x28, 0xbf,
  0xda, 0xc4, 0x9a, 0xc3, 0x24, 0xd9, 0x71, 0xe9, 0xbc, 0x31, 0x11, 0x7c,
  0xa7, 0x33, 0x89, 0xd9,
};

const int64_t kNotBefore = 1577836800;
const int64_t kNotAfter = 1893456000;
const int64_t kInside = 1600000000;

void expect_zeros(const unsigned char * p, size_t n) {
  for (size_t i = 0; i < n; i++) {
    EXPECT_EQ(p[i], 0);
  }
}

void expect_self_signed(uint32_t key, const unsigned char * point,
    size_t point_len, const GSEC_X509_Signer * signer) {
  unsigned char serial[1] = {0x01};
  unsigned char der[4096];
  size_t n = 0;
  GSEC_X509_Tbs tbs;
  GSEC_X509 parsed;
  std::memset(&tbs, 0, sizeof tbs);
  tbs.issuer = kName;
  tbs.issuer_len = sizeof kName;
  tbs.subject = kName;
  tbs.subject_len = sizeof kName;
  tbs.not_before = kNotBefore;
  tbs.not_after = kNotAfter;
  tbs.serial = serial;
  tbs.serial_len = 1;
  tbs.subject_key = key;
  tbs.point = point;
  tbs.point_len = point_len;
  tbs.n = signer->n;
  tbs.n_len = signer->n_len;
  tbs.e = signer->e;
  tbs.e_len = signer->e_len;
  tbs.ca = 1;
  tbs.dns = "ca.example";
  tbs.dns_len = 10;
  ASSERT_EQ(gsec_x509_issue(&tbs, signer, der, sizeof der, &n), GSEC_OK);
  ASSERT_EQ(gsec_x509_parse(der, n, &parsed), GSEC_OK);
  EXPECT_EQ(parsed.key, key);
  EXPECT_EQ(parsed.ca, 1);
  EXPECT_EQ(parsed.dns_san, 1);
  EXPECT_EQ(parsed.not_before, kNotBefore);
  EXPECT_EQ(parsed.not_after, kNotAfter);
  EXPECT_EQ(gsec_x509_signed_by(&parsed, &parsed), GSEC_OK);
  EXPECT_EQ(gsec_x509_path(der, n, nullptr, nullptr, 0, der, n, kInside),
      GSEC_OK);
  EXPECT_EQ(gsec_x509_hostname(&parsed, "ca.example", 10), GSEC_OK);
}

} /* namespace */

TEST(X509Issue, SelfSignedP256Validates) {
  unsigned char scalar[GSEC_ECDSA_P256_LEN];
  unsigned char point[GSEC_ECDSA_P256_PUBLIC_LEN];
  GSEC_X509_Signer signer;
  std::memset(scalar, 0, sizeof scalar);
  scalar[sizeof scalar - 1] = 1;
  ASSERT_EQ(gsec_ecdsa_p256_public(scalar, point), GSEC_OK);
  std::memset(&signer, 0, sizeof signer);
  signer.key = GSEC_X509_P256;
  signer.d = scalar;
  signer.d_len = sizeof scalar;
  expect_self_signed(GSEC_X509_P256, point, sizeof point, &signer);
}

TEST(X509Issue, SelfSignedP384Validates) {
  unsigned char scalar[GSEC_ECDSA_P384_LEN];
  unsigned char point[GSEC_ECDSA_P384_PUBLIC_LEN];
  GSEC_X509_Signer signer;
  std::memset(scalar, 0, sizeof scalar);
  scalar[sizeof scalar - 1] = 1;
  ASSERT_EQ(gsec_ecdsa_p384_public(scalar, point), GSEC_OK);
  std::memset(&signer, 0, sizeof signer);
  signer.key = GSEC_X509_P384;
  signer.d = scalar;
  signer.d_len = sizeof scalar;
  expect_self_signed(GSEC_X509_P384, point, sizeof point, &signer);
}

TEST(X509Issue, SelfSignedEd25519Validates) {
  unsigned char seed[GSEC_ED25519_LEN];
  unsigned char point[GSEC_ED25519_LEN];
  GSEC_X509_Signer signer;
  std::memset(seed, 0, sizeof seed);
  seed[sizeof seed - 1] = 1;
  ASSERT_EQ(gsec_ed25519_public(seed, point), GSEC_OK);
  std::memset(&signer, 0, sizeof signer);
  signer.key = GSEC_X509_ED25519;
  signer.d = seed;
  signer.d_len = sizeof seed;
  expect_self_signed(GSEC_X509_ED25519, point, sizeof point, &signer);
}

TEST(X509Issue, SelfSignedRsaValidates) {
  GSEC_X509_Signer signer;
  std::memset(&signer, 0, sizeof signer);
  signer.key = GSEC_X509_RSA;
  signer.hash = GSEC_RSA_SHA256;
  signer.n = kRsaN;
  signer.n_len = sizeof kRsaN;
  signer.e = kRsaE;
  signer.e_len = sizeof kRsaE;
  signer.d = kRsaD;
  signer.d_len = sizeof kRsaD;
  expect_self_signed(GSEC_X509_RSA, nullptr, 0, &signer);
}

TEST(X509Issue, FailureWipesTheBuffer) {
  unsigned char buf[64];
  size_t n = 99;
  GSEC_X509_Tbs tbs;
  GSEC_X509_Signer signer;
  unsigned char scalar[GSEC_ECDSA_P256_LEN];
  unsigned char point[GSEC_ECDSA_P256_PUBLIC_LEN];

  EXPECT_EQ(gsec_x509_issue(nullptr, nullptr, nullptr, sizeof buf, &n),
      GSEC_ERR_INVALID);
  EXPECT_EQ(n, 99u);

  std::memset(buf, 0xa5, sizeof buf);
  EXPECT_EQ(gsec_x509_issue(nullptr, nullptr, buf, sizeof buf, nullptr),
      GSEC_ERR_INVALID);
  expect_zeros(buf, sizeof buf);
  EXPECT_EQ(n, 99u);

  std::memset(buf, 0xa5, sizeof buf);
  std::memset(&tbs, 0, sizeof tbs);
  std::memset(&signer, 0, sizeof signer);
  EXPECT_EQ(gsec_x509_issue(&tbs, &signer, buf, sizeof buf, &n),
      GSEC_ERR_INVALID);
  expect_zeros(buf, sizeof buf);
  EXPECT_EQ(n, 99u);

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
  tbs.serial = scalar;
  tbs.serial_len = 1;
  tbs.subject_key = GSEC_X509_P256;
  tbs.point = point;
  tbs.point_len = sizeof point;
  signer.key = GSEC_X509_P256;
  signer.d = scalar;
  signer.d_len = sizeof scalar;
  std::memset(buf, 0xa5, sizeof buf);
  n = 99;
  EXPECT_EQ(gsec_x509_issue(&tbs, &signer, buf, sizeof buf, &n),
      GSEC_ERR_LIMIT);
  expect_zeros(buf, sizeof buf);
  EXPECT_EQ(n, 99u);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
