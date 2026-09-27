/**
 * @file
 *
 * A basic OCSP response OpenSSL produced for the revoked leaf.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <vector>

namespace {

std::vector<unsigned char> load(const char * name) {
  std::ifstream in(gsectest::data_dir() + "/certs/" + name, std::ios::binary);
  EXPECT_TRUE(in.good()) << name;
  return std::vector<unsigned char>(std::istreambuf_iterator<char>(in),
      std::istreambuf_iterator<char>());
}

const unsigned char kSerial[] = {
  0x1d, 0xf0, 0x17, 0x04, 0x5e, 0xa3, 0x08, 0x80, 0x5b, 0x21,
  0x9a, 0x09, 0x22, 0xc6, 0xe6, 0xb4, 0x83, 0xc3, 0x15, 0x50
};

const int64_t kRevokedAt = 1767225600;

} /* namespace */

TEST(Ocsp, LeafIsRevoked) {
  auto ocsp_der = load("leaf.ocsp");
  auto ca_der = load("ca.der");
  GSEC_Ocsp ocsp;
  GSEC_X509 ca;
  unsigned char name_hash[GSEC_SHA1_DIGEST_LEN];
  unsigned char key_hash[GSEC_SHA1_DIGEST_LEN];
  unsigned char point[1u + 64u];
  uint32_t status = 99;
  int64_t when = 0;
  ASSERT_EQ(gsec_ocsp_parse(ocsp_der.data(), ocsp_der.size(), &ocsp), GSEC_OK);
  ASSERT_EQ(gsec_x509_parse(ca_der.data(), ca_der.size(), &ca), GSEC_OK);
  EXPECT_EQ(gsec_ocsp_signed_by(&ocsp, &ca), GSEC_OK);
  ASSERT_EQ(gsec_sha1(ca.subject, ca.subject_len, name_hash), GSEC_OK);
  point[0] = 0x04;
  ASSERT_EQ(ca.point_len, 64u);
  std::memcpy(point + 1, ca.point, ca.point_len);
  ASSERT_EQ(gsec_sha1(point, sizeof point, key_hash), GSEC_OK);
  ASSERT_EQ(gsec_ocsp_status(&ocsp, GSEC_HMAC_SHA1, name_hash, sizeof name_hash,
      key_hash, sizeof key_hash, kSerial, sizeof kSerial, &status, &when),
      GSEC_OK);
  EXPECT_EQ(status, GSEC_OCSP_REVOKED);
  EXPECT_EQ(when, kRevokedAt);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
