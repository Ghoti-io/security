/**
 * @file
 *
 * libFuzzer harness for P-256 ECDH.
 *
 * A peer that decodes is multiplied twice and the products agree. A peer
 * that does not decode is rejected and the output is wiped.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/ecdh_p256.h>
#include <ghoti.io/security/secret.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char scalar[GSEC_P256_LEN];
  unsigned char peer[GSEC_P256_PUBLIC_LEN];
  unsigned char out[GSEC_P256_LEN];
  unsigned char again[GSEC_P256_LEN];
  size_t i;
  GSEC_Result result;

  for (i = 0; i < sizeof scalar; i++) {
    scalar[i] = 0;
  }
  for (i = 0; i < sizeof peer; i++) {
    peer[i] = 0;
  }
  for (i = 0; i < sizeof scalar && i < size; i++) {
    scalar[i] = data[i];
  }
  for (i = 0; i < sizeof peer && sizeof scalar + i < size; i++) {
    peer[i] = data[sizeof scalar + i];
  }
  result = gsec_ecdh_p256(scalar, peer, out);
  if (result != GSEC_OK && result != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  if (result == GSEC_ERR_INVALID) {
    for (i = 0; i < sizeof out; i++) {
      if (out[i] != 0) {
        __builtin_trap();
      }
    }
  } else if (gsec_ecdh_p256(scalar, peer, again) != GSEC_OK ||
      gsec_equal(out, again, sizeof out) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_ecdh_p256(nullptr, peer, out) != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  gsec_wipe(scalar, sizeof scalar);
  gsec_wipe(out, sizeof out);
  gsec_wipe(again, sizeof again);
  return 0;
}
