/**
 * @file
 *
 * P-384 ECDH against one OpenSSL shared secret.
 *
 * A peer that is not on the curve is rejected and the output is wiped.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstring>

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

void unhex(const char * text, unsigned char * out, size_t n) {
  size_t i;
  ASSERT_EQ(std::strlen(text), n * 2);
  for (i = 0; i < n; i++) {
    int hi = nibble(text[i * 2]);
    int lo = nibble(text[i * 2 + 1]);
    ASSERT_GE(hi, 0);
    ASSERT_GE(lo, 0);
    out[i] = static_cast<unsigned char>((hi << 4) | lo);
  }
}

} /* namespace */

TEST(EcdhP384, MatchesOpenSsl) {
  unsigned char scalar[GSEC_P384_LEN];
  unsigned char peer[GSEC_P384_PUBLIC_LEN];
  unsigned char want[GSEC_P384_LEN];
  unsigned char pub[GSEC_P384_PUBLIC_LEN];
  unsigned char shared[GSEC_P384_LEN];
  /* OpenSSL 3.5.7, secp384r1. The public key omits the 0x04 prefix. */
  unhex("d63e1d349c517dfa43a175ca271fcc2cfd30b2ce67b71941aaf375f4457ecef2"
      "f7c99e9d784b6a753c3311b04e4f3aab", scalar, sizeof scalar);
  unhex("c954614548964d210c0709fe4c9bd716f1598408da7b0d3edbaaa0e7181637c2"
      "e47d638794b7b590491f42b57bb8ad503269c60eb8394fba2de7b47e7f8468cdff"
      "0803a6554663d1afbdee9848f8f1e088239f2d9a0d7fd1d6b3e92473a5d628",
      peer, sizeof peer);
  unhex("1e955d75768586d483ab61296a77aba8d88da2283506d9c6851acf95e41bd092"
      "e8e0ad46e2ff9ad632d87a49b3d397cd", want, sizeof want);
  ASSERT_EQ(gsec_ecdh_p384(scalar, peer, shared), GSEC_OK);
  EXPECT_EQ(std::memcmp(shared, want, sizeof want), 0);
  ASSERT_EQ(gsec_ecdh_p384_public(scalar, pub), GSEC_OK);
  unhex("8e51fe4a21b37cf5ff04061608b255018a68c81acd264c5c44ae61b26be7dad9"
      "071e8eb8ec21b3eb5da0f3f1a56e03995ed533544c96b03f30fa46370d0aab3001"
      "528cb0667635b899637ed1652a83729d4c15f932b7f8a758bb6fbad879b627",
      peer, sizeof peer);
  EXPECT_EQ(std::memcmp(pub, peer, sizeof pub), 0);
}

TEST(EcdhP384, RejectsABadPeer) {
  unsigned char scalar[GSEC_P384_LEN];
  unsigned char peer[GSEC_P384_PUBLIC_LEN];
  unsigned char out[GSEC_P384_LEN];
  std::memset(scalar, 0x3c, sizeof scalar);
  std::memset(peer, 0x02, sizeof peer);
  std::memset(out, 0xa5, sizeof out);
  EXPECT_EQ(gsec_ecdh_p384(scalar, peer, out), GSEC_ERR_INVALID);
  EXPECT_EQ(out[0], 0);
  EXPECT_EQ(gsec_ecdh_p384(nullptr, peer, out), GSEC_ERR_INVALID);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
