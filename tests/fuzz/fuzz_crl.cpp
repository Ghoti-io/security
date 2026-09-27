/**
 * @file
 *
 * libFuzzer harness for CRL parsing.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/crl.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  GSEC_Crl crl;
  GSEC_Result result;
  unsigned char serial[1] = {0x01};

  if (size > GSEC_X509_DER_MAX) {
    size = GSEC_X509_DER_MAX;
  }
  result = gsec_crl_parse(data, size, &crl);
  if (result != GSEC_OK && result != GSEC_ERR_CORRUPT &&
      result != GSEC_ERR_UNSUPPORTED && result != GSEC_ERR_LIMIT &&
      result != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  if (result == GSEC_OK) {
    result = gsec_crl_contains(&crl, serial, 1);
    if (result != GSEC_OK && result != GSEC_ERR_MISMATCH &&
        result != GSEC_ERR_CORRUPT && result != GSEC_ERR_INVALID) {
      __builtin_trap();
    }
  }
  return 0;
}
