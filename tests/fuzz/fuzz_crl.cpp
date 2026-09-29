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
  GSEC_Crl crl;
  GSEC_Result result;
  GSEC_Result parsed;
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
  parsed = result;
  if (parsed == GSEC_OK) {
    result = gsec_crl_contains(&crl, serial, 1);
    if (result != GSEC_OK && result != GSEC_ERR_MISMATCH &&
        result != GSEC_ERR_CORRUPT && result != GSEC_ERR_INVALID) {
      __builtin_trap();
    }
  }
  {
    /* `parsed`, not `result`: the lookup above overwrites `result`, and
     * comparing the second parse against a lookup's answer is how this
     * invariant reported a non-deterministic parser that was nothing of the
     * kind. */
    GSEC_Crl twice;
    if (gsec_crl_parse(data, size, &twice) != parsed) {
      __builtin_trap();
    }
  }
  if (parsed == GSEC_OK) {
    inside(data, size, crl.tbs, crl.tbs_len);
    inside(data, size, crl.issuer, crl.issuer_len);
    inside(data, size, crl.revoked, crl.revoked_len);
  }
  return 0;
}
