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


/* A view a parser returned has to point into the bytes it was given. NULL with
 * a zero length is how an absent field is spelled. */
static void inside(const uint8_t * data, size_t size, const void * view,
    size_t view_len) {
  const uint8_t * p = (const uint8_t *)view;

  if (p == nullptr) {
    if (view_len != 0) {
      __builtin_trap();
    }
    return;
  }
  if (p < data || p > data + size || view_len > (size_t)(data + size - p)) {
    __builtin_trap();
  }
}

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
  {
    GSEC_Ocsp twice;
    if (gsec_ocsp_parse(data, size, &twice) != result) {
      __builtin_trap();
    }
  }
  if (result == GSEC_OK) {
    inside(data, size, ocsp.tbs, ocsp.tbs_len);
    inside(data, size, ocsp.responses, ocsp.responses_len);
  }
  return 0;
}
