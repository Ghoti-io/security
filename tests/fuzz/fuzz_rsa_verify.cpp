/**
 * @file
 *
 * libFuzzer harness for RSA verification.
 *
 * The inputs are a modulus, an exponent, and a signature. The result is
 * one of the public status codes. A run does not crash.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/rsa.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  size_t n_len;
  size_t e_len;
  size_t sig_len;
  GSEC_Result result;

  if (size > 96) {
    size = 96;
  }
  n_len = size / 3;
  e_len = size / 3;
  sig_len = size - n_len - e_len;
  result = gsec_rsa_pkcs1_v15_verify(GSEC_RSA_SHA256, data, n_len,
      data + n_len, e_len, data, sig_len, data, sig_len);
  if (result != GSEC_OK && result != GSEC_ERR_MISMATCH &&
      result != GSEC_ERR_INVALID && result != GSEC_ERR_LIMIT) {
    __builtin_trap();
  }
  result = gsec_rsa_pss_verify(GSEC_RSA_SHA256, GSEC_RSA_SHA1, data, n_len,
      data + n_len, e_len, nullptr, 0, data, sig_len, 0);
  if (result != GSEC_OK && result != GSEC_ERR_MISMATCH &&
      result != GSEC_ERR_INVALID && result != GSEC_ERR_LIMIT) {
    __builtin_trap();
  }
  if (gsec_rsa_pkcs1_v15_verify(0, data, n_len, data, e_len, nullptr, 0,
      data, sig_len) != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  return 0;
}
