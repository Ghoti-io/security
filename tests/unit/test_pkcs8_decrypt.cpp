/**
 * @file
 *
 * PBES2 PKCS#8 against an OpenSSL EncryptedPrivateKeyInfo.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstdint>
#include <fstream>
#include <vector>

namespace {

std::vector<unsigned char> load(const char * name) {
  std::ifstream in(gsectest::data_dir() + "/certs/" + name, std::ios::binary);
  EXPECT_TRUE(in.good()) << name;
  return std::vector<unsigned char>(std::istreambuf_iterator<char>(in),
      std::istreambuf_iterator<char>());
}

} /* namespace */

TEST(Pkcs8Decrypt, OpensTheLeafKey) {
  auto enc = load("leaf.p8");
  auto plain = load("leaf.plain.p8");
  std::vector<unsigned char> out(enc.size());
  size_t n = 0;
  GSEC_Pkcs8 got;
  GSEC_Pkcs8 expect;
  ASSERT_EQ(gsec_pkcs8_decrypt(enc.data(), enc.size(), "secret", 6,
      out.data(), out.size(), &n, nullptr), GSEC_OK);
  ASSERT_EQ(gsec_pkcs8_parse(out.data(), n, &got), GSEC_OK);
  ASSERT_EQ(gsec_pkcs8_parse(plain.data(), plain.size(), &expect), GSEC_OK);
  EXPECT_EQ(got.kind, expect.kind);
  ASSERT_EQ(got.scalar_len, expect.scalar_len);
  EXPECT_EQ(gsec_equal(got.scalar, expect.scalar, got.scalar_len), GSEC_OK);
}

TEST(Pkcs8Decrypt, OpensTheOlderSchemes) {
  static const char * names[] = {
    "pbe-md5-des.p8",
    "pbe-md5-rc2-64.p8",
    "pbe-sha1-des.p8",
    "pbe-sha1-rc2-64.p8",
    "pbe-sha1-3des.p8",
    "pbe-sha1-2des.p8",
    "pbe-sha1-rc2-128.p8",
    "pbe-sha1-rc2-40.p8",
    "pbe-sha1-rc4-128.p8",
    "pbe-sha1-rc4-40.p8",
  };
  auto plain = load("leaf.plain.p8");
  GSEC_Pkcs8 expect;
  size_t i;
  ASSERT_EQ(gsec_pkcs8_parse(plain.data(), plain.size(), &expect), GSEC_OK);
  for (i = 0; i < sizeof names / sizeof names[0]; i++) {
    auto enc = load(names[i]);
    std::vector<unsigned char> out(enc.size());
    size_t n = 0;
    GSEC_Pkcs8 got;
    SCOPED_TRACE(names[i]);
    ASSERT_EQ(gsec_pkcs8_decrypt(enc.data(), enc.size(), "secret", 6,
        out.data(), out.size(), &n, nullptr), GSEC_OK);
    ASSERT_EQ(gsec_pkcs8_parse(out.data(), n, &got), GSEC_OK);
    ASSERT_EQ(got.scalar_len, expect.scalar_len);
    EXPECT_EQ(gsec_equal(got.scalar, expect.scalar, got.scalar_len), GSEC_OK);
  }
}

TEST(Pkcs8Decrypt, WrongPasswordWipes) {
  auto enc = load("leaf.p8");
  std::vector<unsigned char> out(enc.size(), 0xa5);
  size_t n = 99;
  ASSERT_EQ(gsec_pkcs8_decrypt(enc.data(), enc.size(), "nope", 4,
      out.data(), out.size(), &n, nullptr), GSEC_ERR_MISMATCH);
  EXPECT_EQ(n, 99u);
  for (unsigned char byte : out) {
    EXPECT_EQ(byte, 0);
  }
}

TEST(Pkcs8Decrypt, IterationCountAboveTheCapIsRefused) {
  /* overiter.p8 asks for 10,000,001 iterations, one past the default
   * ceiling. It must be refused before any derivation runs: at roughly
   * 0.9 microseconds an iteration this is nine seconds of CPU that an
   * attacker chose. */
  auto enc = load("overiter.p8");
  unsigned char out[4096];
  size_t out_len = 0;
  ASSERT_GT(enc.size(), 0u);
  EXPECT_EQ(gsec_pkcs8_decrypt(enc.data(), enc.size(), "secret", 6, out,
      sizeof out, &out_len, nullptr), GSEC_ERR_LIMIT);

  /* And it is the cap that refused it, not the file being malformed: raise
   * the ceiling past what the file asks for and the answer changes. A wrong
   * password would be GSEC_ERR_MISMATCH; the point is only that it is no
   * longer GSEC_ERR_LIMIT. */
  GSEC_Limits limits;
  gsec_limits_default(&limits);
  limits.max_pbe_iterations = 1;
  EXPECT_EQ(gsec_pkcs8_decrypt(enc.data(), enc.size(), "secret", 6, out,
      sizeof out, &out_len, &limits), GSEC_ERR_LIMIT);
}

TEST(Pkcs8Decrypt, LoweredCapRefusesAnOrdinaryFile) {
  auto enc = load("leaf.p8");
  unsigned char out[4096];
  size_t out_len = 0;
  GSEC_Limits limits;
  gsec_limits_default(&limits);
  ASSERT_EQ(gsec_pkcs8_decrypt(enc.data(), enc.size(), "secret", 6, out,
      sizeof out, &out_len, &limits), GSEC_OK);
  limits.max_pbe_iterations = 1;
  EXPECT_EQ(gsec_pkcs8_decrypt(enc.data(), enc.size(), "secret", 6, out,
      sizeof out, &out_len, &limits), GSEC_ERR_LIMIT);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
