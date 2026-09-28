/**
 * @file
 *
 * A PKCS#12 file OpenSSL wrote: a leaf key, the leaf, and its CA.
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

TEST(Pkcs12, OpensKeyAndCerts) {
  auto p12 = load("leaf.p12");
  auto plain = load("leaf.plain.p8");
  unsigned char scratch[8192];
  GSEC_Pkcs12 bag;
  GSEC_Pkcs8 got;
  GSEC_Pkcs8 expect;
  GSEC_X509 cert;
  size_t i;
  int saw_leaf = 0;
  ASSERT_EQ(gsec_pkcs12_open(p12.data(), p12.size(), "secret", 6, scratch,
      sizeof scratch, &bag), GSEC_OK);
  ASSERT_NE(bag.key, nullptr);
  ASSERT_EQ(gsec_pkcs8_parse(bag.key, bag.key_len, &got), GSEC_OK);
  ASSERT_EQ(gsec_pkcs8_parse(plain.data(), plain.size(), &expect), GSEC_OK);
  ASSERT_EQ(got.scalar_len, expect.scalar_len);
  EXPECT_EQ(gsec_equal(got.scalar, expect.scalar, got.scalar_len), GSEC_OK);
  EXPECT_GE(bag.cert_count, 2u);
  for (i = 0; i < bag.cert_count; i++) {
    ASSERT_EQ(gsec_x509_parse(bag.certs[i], bag.cert_lens[i], &cert), GSEC_OK);
    if (cert.dns_san) {
      saw_leaf = 1;
      EXPECT_EQ(gsec_x509_hostname(&cert, "leaf.example", 12), GSEC_OK);
    }
  }
  EXPECT_EQ(saw_leaf, 1);
}

TEST(Pkcs12, OpensATraditionalBag) {
  static const char * names[] = {
    "legacy-3des-rc2.p12",
    "legacy-rc4-rc2.p12",
  };
  auto plain = load("leaf.plain.p8");
  GSEC_Pkcs8 expect;
  size_t i;
  ASSERT_EQ(gsec_pkcs8_parse(plain.data(), plain.size(), &expect), GSEC_OK);
  for (i = 0; i < sizeof names / sizeof names[0]; i++) {
    auto p12 = load(names[i]);
    unsigned char scratch[8192];
    GSEC_Pkcs12 bag;
    GSEC_Pkcs8 got;
    SCOPED_TRACE(names[i]);
    ASSERT_EQ(gsec_pkcs12_open(p12.data(), p12.size(), "secret", 6, scratch,
        sizeof scratch, &bag), GSEC_OK);
    ASSERT_NE(bag.key, nullptr);
    ASSERT_EQ(gsec_pkcs8_parse(bag.key, bag.key_len, &got), GSEC_OK);
    ASSERT_EQ(got.scalar_len, expect.scalar_len);
    EXPECT_EQ(gsec_equal(got.scalar, expect.scalar, got.scalar_len), GSEC_OK);
    EXPECT_GE(bag.cert_count, 1u);
  }
}

TEST(Pkcs12, WrongPasswordFailsTheMac) {
  auto p12 = load("leaf.p12");
  unsigned char scratch[64];
  GSEC_Pkcs12 bag;
  EXPECT_EQ(gsec_pkcs12_open(p12.data(), p12.size(), "nope", 4, scratch,
      sizeof scratch, &bag), GSEC_ERR_MISMATCH);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
