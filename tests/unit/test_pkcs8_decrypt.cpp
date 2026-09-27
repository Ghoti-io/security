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
      out.data(), out.size(), &n), GSEC_OK);
  ASSERT_EQ(gsec_pkcs8_parse(out.data(), n, &got), GSEC_OK);
  ASSERT_EQ(gsec_pkcs8_parse(plain.data(), plain.size(), &expect), GSEC_OK);
  EXPECT_EQ(got.kind, expect.kind);
  ASSERT_EQ(got.scalar_len, expect.scalar_len);
  EXPECT_EQ(gsec_equal(got.scalar, expect.scalar, got.scalar_len), GSEC_OK);
}

TEST(Pkcs8Decrypt, WrongPasswordWipes) {
  auto enc = load("leaf.p8");
  std::vector<unsigned char> out(enc.size(), 0xa5);
  size_t n = 99;
  ASSERT_EQ(gsec_pkcs8_decrypt(enc.data(), enc.size(), "nope", 4,
      out.data(), out.size(), &n), GSEC_ERR_MISMATCH);
  EXPECT_EQ(n, 99u);
  for (unsigned char byte : out) {
    EXPECT_EQ(byte, 0);
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
