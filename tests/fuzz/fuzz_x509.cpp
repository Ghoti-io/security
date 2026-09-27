/**
 * @file
 *
 * libFuzzer harness for X.509 parse and hostname matching.
 *
 * Path validation is not run here. It signs nothing and it allocates
 * nothing beyond the result struct.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/x509.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  GSEC_X509 cert;
  GSEC_Result result;

  if (size > GSEC_X509_DER_MAX) {
    size = GSEC_X509_DER_MAX;
  }
  result = gsec_x509_parse(data, size, &cert);
  if (result != GSEC_OK && result != GSEC_ERR_CORRUPT &&
      result != GSEC_ERR_UNSUPPORTED && result != GSEC_ERR_LIMIT &&
      result != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  if (result == GSEC_OK && size > 0) {
    result = gsec_x509_hostname(&cert, (const char *)data, size > 64 ? 64 : size);
    if (result != GSEC_OK && result != GSEC_ERR_MISMATCH &&
        result != GSEC_ERR_INVALID) {
      __builtin_trap();
    }
  }
  return 0;
}
