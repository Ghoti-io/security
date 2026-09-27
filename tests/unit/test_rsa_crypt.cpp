/**
 * @file
 *
 * RSA encryption against one OpenSSL 3.5.7 ciphertext, and a round trip.
 *
 * PKCS#1 v1.5 is the TLS 1.2 key-transport encoding. OAEP uses SHA-256
 * and an empty label, which is OpenSSL's default. A bad ciphertext is
 * rejected and the output is wiped.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

int nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  return -1;
}

std::vector<unsigned char> unhex(const char * text) {
  std::string hex(text);
  std::vector<unsigned char> out;
  EXPECT_EQ(hex.size() % 2, 0u);
  for (size_t i = 0; i < hex.size(); i += 2) {
    int hi = nibble(hex[i]);
    int lo = nibble(hex[i + 1]);
    EXPECT_GE(hi, 0);
    EXPECT_GE(lo, 0);
    out.push_back(static_cast<unsigned char>((hi << 4) | lo));
  }
  return out;
}

const char * kN =
    "00aae20ff85bc842f982733037c8fce3572dfa87141ce65be166b981a1237286"
    "d2ccdfc276fdc661d0dce90f8f1d00a135b27c49c29ff6f99c455c233e510b61"
    "460b408a7d4465c4e8dbb42e728f14ea3a2e1460a508e310d8db1a19cd462f89"
    "d539c4f5805abb8d078608738644357722927c7418def1a8babd09b2b8c77b3799";
const char * kD =
    "0efd77b32cb1fb9611a8732161a3357a2f515bca1ae2e64a768d6d5eaa52609b"
    "5b5781a2988e6f8437ecc5eda2f8ac2b9eb5a26ecd43880ffa51a3d1d2a031ef"
    "2357909ff729cf5bd781bc57b0ac0761c6085fce9202103c46730d123c43f15a"
    "1bb3785f5bea7086a386a0d94fac4bc4187fd78e089a0edd20703c2fb76fdf11";
const char * kMsg =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "202122232425262728292a2b2c2d2e2f";
const char * kPkcs1 =
    "6785abefb8a0d07245c49d05d255ccfa77e4625788efa30532ac52d5e111f332"
    "15967d24ad7561426fd45691fd58d11a85e4d6da278ebb9de2ac6af63838c4a2"
    "93543dee932a8e2ea8bd4d1bf29ea5191fdf1eeb49768832b09a7e2768d8951e"
    "5a165512edbcdf370080450e2dfc33875e4f55ee73374861e8d3d5e757a4b3a7";
const char * kOaep =
    "84d68ad865f5c4825d6ca733fe4962abad72d09fc3251ddc8fc959c858a7854c"
    "98fc424dd4eb1cb5d8cc72c279796eb3f4d963abd6c28d3cedf19fd573af9be5"
    "8e87c627ebc84eafe4f1e4ccedd7fc679f90fe61f78b336767a1ccf17b1a8468"
    "1fc7fad0aee06b346f84412eb8e186b01b948119a40f673840bfc61027857403";
const char * kShort = "6f6165702d6c6162656c2d6d7367";

} /* namespace */

TEST(RsaCrypt, DecryptsOpenSslPkcs1) {
  auto n = unhex(kN);
  auto d = unhex(kD);
  auto msg = unhex(kMsg);
  auto ct = unhex(kPkcs1);
  unsigned char e[3] = {0x01, 0x00, 0x01};
  unsigned char got[64];
  size_t got_len = 0;
  std::memset(got, 0xa5, sizeof got);
  ASSERT_EQ(gsec_rsa_pkcs1_v15_decrypt(n.data(), n.size(), e, sizeof e,
      d.data(), d.size(), ct.data(), ct.size(), got, sizeof got, &got_len),
      GSEC_OK);
  ASSERT_EQ(got_len, msg.size());
  EXPECT_EQ(std::memcmp(got, msg.data(), msg.size()), 0);
}

TEST(RsaCrypt, DecryptsOpenSslOaep) {
  auto n = unhex(kN);
  auto d = unhex(kD);
  auto ct = unhex(kOaep);
  auto msg = unhex(kShort);
  unsigned char e[3] = {0x01, 0x00, 0x01};
  unsigned char got[64];
  size_t got_len = 0;
  ASSERT_EQ(gsec_rsa_oaep_decrypt(GSEC_RSA_SHA256, n.data(), n.size(), e,
      sizeof e, d.data(), d.size(), nullptr, 0, ct.data(), ct.size(), got,
      sizeof got, &got_len), GSEC_OK);
  ASSERT_EQ(got_len, msg.size());
  EXPECT_EQ(std::memcmp(got, msg.data(), msg.size()), 0);
}

TEST(RsaCrypt, RoundTrip) {
  auto n = unhex(kN);
  auto d = unhex(kD);
  unsigned char e[3] = {0x01, 0x00, 0x01};
  unsigned char msg[16];
  unsigned char ct[128];
  unsigned char got[16];
  size_t got_len = 0;
  static const unsigned char label[5] = {'l', 'a', 'b', 'e', 'l'};
  std::memset(msg, 0x3c, sizeof msg);
  ASSERT_EQ(gsec_rsa_pkcs1_v15_encrypt(n.data(), n.size(), e, sizeof e, msg,
      sizeof msg, ct, sizeof ct), GSEC_OK);
  ASSERT_EQ(gsec_rsa_pkcs1_v15_decrypt(n.data(), n.size(), e, sizeof e,
      d.data(), d.size(), ct, sizeof ct, got, sizeof got, &got_len), GSEC_OK);
  EXPECT_EQ(got_len, sizeof msg);
  EXPECT_EQ(std::memcmp(got, msg, sizeof msg), 0);
  ASSERT_EQ(gsec_rsa_oaep_encrypt(GSEC_RSA_SHA256, n.data(), n.size(), e,
      sizeof e, label, sizeof label, msg, sizeof msg, ct, sizeof ct),
      GSEC_OK);
  std::memset(got, 0, sizeof got);
  got_len = 0;
  ASSERT_EQ(gsec_rsa_oaep_decrypt(GSEC_RSA_SHA256, n.data(), n.size(), e,
      sizeof e, d.data(), d.size(), label, sizeof label, ct, sizeof ct, got,
      sizeof got, &got_len), GSEC_OK);
  EXPECT_EQ(got_len, sizeof msg);
  EXPECT_EQ(std::memcmp(got, msg, sizeof msg), 0);
  EXPECT_EQ(gsec_rsa_oaep_decrypt(GSEC_RSA_SHA256, n.data(), n.size(), e,
      sizeof e, d.data(), d.size(), nullptr, 0, ct, sizeof ct, got,
      sizeof got, &got_len), GSEC_ERR_MISMATCH);
}

TEST(RsaCrypt, RejectsBadPadding) {
  auto n = unhex(kN);
  auto d = unhex(kD);
  auto ct = unhex(kPkcs1);
  unsigned char e[3] = {0x01, 0x00, 0x01};
  unsigned char got[64];
  size_t got_len = 99;
  ct[20] ^= 0x01;
  std::memset(got, 0xa5, sizeof got);
  EXPECT_EQ(gsec_rsa_pkcs1_v15_decrypt(n.data(), n.size(), e, sizeof e,
      d.data(), d.size(), ct.data(), ct.size(), got, sizeof got, &got_len),
      GSEC_ERR_MISMATCH);
  EXPECT_EQ(got[0], 0);
  EXPECT_EQ(got_len, 99u);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
