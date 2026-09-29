/**
 * @file
 *
 * A basic OCSP response: the happy path, and every way it has to fail.
 *
 * This file used to hold one test and no negative assertion at all, which
 * the audit found by mutating the CertID serial comparison so that every
 * serial matched - reporting one certificate's revocation status for another
 * - and watching `make test` pass. It is the function a caller asks "is this
 * certificate revoked", so the answers it must refuse to give are the point.
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

/* The two hashes a CertID is keyed by: the issuer's subject name, and its
 * public key as the uncompressed point. */
struct Id {
  unsigned char name[GSEC_SHA1_DIGEST_LEN];
  unsigned char key[GSEC_SHA1_DIGEST_LEN];
};

Id id_of(const GSEC_X509 & ca) {
  Id id;
  unsigned char point[1u + 64u];
  EXPECT_EQ(gsec_sha1(ca.subject, ca.subject_len, id.name), GSEC_OK);
  point[0] = 0x04;
  EXPECT_EQ(ca.point_len, 64u);
  std::memcpy(point + 1, ca.point, ca.point_len);
  EXPECT_EQ(gsec_sha1(point, sizeof point, id.key), GSEC_OK);
  return id;
}

GSEC_Result status_of(const GSEC_Ocsp & ocsp, const Id & id,
    const unsigned char * serial, size_t serial_len,
    GSEC_Ocsp_Single * out) {
  return gsec_ocsp_status(&ocsp, GSEC_HMAC_SHA1, id.name, sizeof id.name,
      id.key, sizeof id.key, serial, serial_len, out);
}

} /* namespace */

TEST(Ocsp, LeafIsRevoked) {
  auto ocsp_der = load("leaf.ocsp");
  auto ca_der = load("ca.der");
  GSEC_Ocsp ocsp;
  GSEC_X509 ca;
  GSEC_Ocsp_Single single;
  ASSERT_EQ(gsec_ocsp_parse(ocsp_der.data(), ocsp_der.size(), &ocsp), GSEC_OK);
  ASSERT_EQ(gsec_x509_parse(ca_der.data(), ca_der.size(), &ca), GSEC_OK);
  EXPECT_EQ(gsec_ocsp_signed_by(&ocsp, &ca), GSEC_OK);
  Id id = id_of(ca);
  ASSERT_EQ(status_of(ocsp, id, kSerial, sizeof kSerial, &single), GSEC_OK);
  EXPECT_EQ(single.status, GSEC_OCSP_REVOKED);
  EXPECT_EQ(single.revoked_at, kRevokedAt);
}

TEST(Ocsp, FreshnessIsVisible) {
  /* The response says when it was produced and what instant it describes.
   * Without these a caller cannot tell a current answer from one replayed
   * out of a capture, which is the cheapest attack on revocation there is. */
  auto ocsp_der = load("leaf.ocsp");
  auto ca_der = load("ca.der");
  GSEC_Ocsp ocsp;
  GSEC_X509 ca;
  GSEC_Ocsp_Single single;
  ASSERT_EQ(gsec_ocsp_parse(ocsp_der.data(), ocsp_der.size(), &ocsp), GSEC_OK);
  ASSERT_EQ(gsec_x509_parse(ca_der.data(), ca_der.size(), &ca), GSEC_OK);
  EXPECT_GT(ocsp.produced_at, 1700000000);
  Id id = id_of(ca);
  ASSERT_EQ(status_of(ocsp, id, kSerial, sizeof kSerial, &single), GSEC_OK);
  EXPECT_GT(single.this_update, 1700000000);
  EXPECT_LE(single.this_update, ocsp.produced_at);
  if (single.have_next_update) {
    EXPECT_GE(single.next_update, single.this_update);
  }
}

TEST(Ocsp, AnotherSerialIsNotThisAnswer) {
  /* The mutation that survived: every serial matching. One byte of the
   * serial changed must be GSEC_ERR_MISMATCH and not a status. */
  auto ocsp_der = load("leaf.ocsp");
  auto ca_der = load("ca.der");
  GSEC_Ocsp ocsp;
  GSEC_X509 ca;
  GSEC_Ocsp_Single single;
  ASSERT_EQ(gsec_ocsp_parse(ocsp_der.data(), ocsp_der.size(), &ocsp), GSEC_OK);
  ASSERT_EQ(gsec_x509_parse(ca_der.data(), ca_der.size(), &ca), GSEC_OK);
  Id id = id_of(ca);

  for (size_t i = 0; i < sizeof kSerial; i++) {
    unsigned char other[sizeof kSerial];
    std::memcpy(other, kSerial, sizeof other);
    other[i] = static_cast<unsigned char>(other[i] ^ 0x01u);
    EXPECT_EQ(status_of(ocsp, id, other, sizeof other, &single),
        GSEC_ERR_MISMATCH) << "serial byte " << i;
  }
  /* A shorter and a longer serial are different serials, not prefixes. */
  EXPECT_EQ(status_of(ocsp, id, kSerial, sizeof kSerial - 1u, &single),
      GSEC_ERR_MISMATCH);
  unsigned char longer[sizeof kSerial + 1u] = {0};
  std::memcpy(longer, kSerial, sizeof kSerial);
  EXPECT_EQ(status_of(ocsp, id, longer, sizeof longer, &single),
      GSEC_ERR_MISMATCH);
}

TEST(Ocsp, AnotherIssuerIsNotThisAnswer) {
  auto ocsp_der = load("leaf.ocsp");
  auto ca_der = load("ca.der");
  GSEC_Ocsp ocsp;
  GSEC_X509 ca;
  GSEC_Ocsp_Single single;
  ASSERT_EQ(gsec_ocsp_parse(ocsp_der.data(), ocsp_der.size(), &ocsp), GSEC_OK);
  ASSERT_EQ(gsec_x509_parse(ca_der.data(), ca_der.size(), &ca), GSEC_OK);

  Id bad_name = id_of(ca);
  bad_name.name[0] = static_cast<unsigned char>(bad_name.name[0] ^ 0x01u);
  EXPECT_EQ(status_of(ocsp, bad_name, kSerial, sizeof kSerial, &single),
      GSEC_ERR_MISMATCH);

  Id bad_key = id_of(ca);
  bad_key.key[19] = static_cast<unsigned char>(bad_key.key[19] ^ 0x80u);
  EXPECT_EQ(status_of(ocsp, bad_key, kSerial, sizeof kSerial, &single),
      GSEC_ERR_MISMATCH);
}

TEST(Ocsp, WrongIssuerDoesNotVerify) {
  auto ocsp_der = load("leaf.ocsp");
  auto other_der = load("p256-ca.der");
  GSEC_Ocsp ocsp;
  GSEC_X509 other;
  ASSERT_EQ(gsec_ocsp_parse(ocsp_der.data(), ocsp_der.size(), &ocsp), GSEC_OK);
  ASSERT_EQ(gsec_x509_parse(other_der.data(), other_der.size(), &other),
      GSEC_OK);
  EXPECT_EQ(gsec_ocsp_signed_by(&ocsp, &other), GSEC_ERR_MISMATCH);
}

TEST(Ocsp, TamperedSignatureDoesNotVerify) {
  auto ca_der = load("ca.der");
  GSEC_X509 ca;
  ASSERT_EQ(gsec_x509_parse(ca_der.data(), ca_der.size(), &ca), GSEC_OK);

  /* Flip one bit inside the signed body. Parsing may still succeed - the
   * bytes stay a valid encoding - but the signature must not. Only the signed
   * body: a response also carries the responder's certificates, which the
   * signature does not cover and which gsec_ocsp_signed_by does not read,
   * because the issuer is the caller's. Flipping a byte out there and
   * expecting a failure would be asserting something untrue. */
  auto base = load("leaf.ocsp");
  GSEC_Ocsp pristine;
  ASSERT_EQ(gsec_ocsp_parse(base.data(), base.size(), &pristine), GSEC_OK);
  size_t tbs_at = static_cast<size_t>(pristine.tbs - base.data());
  ASSERT_LT(tbs_at, base.size());
  ASSERT_LE(tbs_at + pristine.tbs_len, base.size());

  int checked = 0;
  for (size_t i = tbs_at; i < tbs_at + pristine.tbs_len; i += 17) {
    auto bytes = base;
    bytes[i] = static_cast<unsigned char>(bytes[i] ^ 0x01u);
    GSEC_Ocsp ocsp;
    if (gsec_ocsp_parse(bytes.data(), bytes.size(), &ocsp) != GSEC_OK) {
      continue;
    }
    GSEC_Result r = gsec_ocsp_signed_by(&ocsp, &ca);
    EXPECT_NE(r, GSEC_OK) << "byte " << i << " was flipped and it verified";
    checked++;
  }
  EXPECT_GT(checked, 4) << "too few flipped responses parsed for this to mean "
                           "anything";

  /* Not a flip inside the signature: this response is ECDSA, and an ECDSA
   * signature is copied into GSEC_Ocsp::ecdsa_raw rather than left in the
   * caller's buffer, so the parse result does not say where in the input it
   * was. The sweep above is what covers tampering. */
}

TEST(Ocsp, ArgumentsAreChecked) {
  auto ocsp_der = load("leaf.ocsp");
  auto ca_der = load("ca.der");
  GSEC_Ocsp ocsp;
  GSEC_X509 ca;
  GSEC_Ocsp_Single single;
  ASSERT_EQ(gsec_ocsp_parse(ocsp_der.data(), ocsp_der.size(), &ocsp), GSEC_OK);
  ASSERT_EQ(gsec_x509_parse(ca_der.data(), ca_der.size(), &ca), GSEC_OK);
  Id id = id_of(ca);

  EXPECT_EQ(gsec_ocsp_status(nullptr, GSEC_HMAC_SHA1, id.name, sizeof id.name,
      id.key, sizeof id.key, kSerial, sizeof kSerial, &single),
      GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ocsp_status(&ocsp, GSEC_HMAC_SHA1, id.name, sizeof id.name,
      id.key, sizeof id.key, kSerial, sizeof kSerial, nullptr),
      GSEC_ERR_INVALID);
  /* A digest id that is not one of the four, and a length that is not the
   * digest's, are both the caller's mistake rather than a lookup miss. */
  EXPECT_EQ(gsec_ocsp_status(&ocsp, 0xffffu, id.name, sizeof id.name, id.key,
      sizeof id.key, kSerial, sizeof kSerial, &single), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ocsp_status(&ocsp, GSEC_HMAC_SHA1, id.name,
      sizeof id.name - 1u, id.key, sizeof id.key, kSerial, sizeof kSerial,
      &single), GSEC_ERR_INVALID);
  EXPECT_EQ(gsec_ocsp_signed_by(nullptr, &ca), GSEC_ERR_INVALID);
}

TEST(Ocsp, TruncationIsRefused) {
  auto base = load("leaf.ocsp");
  for (size_t n = 1; n < base.size(); n += 11) {
    GSEC_Ocsp ocsp;
    EXPECT_NE(gsec_ocsp_parse(base.data(), n, &ocsp), GSEC_OK)
        << "accepted a response truncated to " << n;
  }
  GSEC_Ocsp ocsp;
  EXPECT_NE(gsec_ocsp_parse(base.data(), 0, &ocsp), GSEC_OK);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
