/**
 * @file
 *
 * libFuzzer harness for OCSP parsing.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/ocsp.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  GSEC_Ocsp ocsp;
  GSEC_Result result;

  if (size > GSEC_X509_DER_MAX) {
    size = GSEC_X509_DER_MAX;
  }
  result = gsec_ocsp_parse(data, size, &ocsp);
  if (result != GSEC_OK && result != GSEC_ERR_CORRUPT &&
      result != GSEC_ERR_UNSUPPORTED && result != GSEC_ERR_LIMIT &&
      result != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  return 0;
}
