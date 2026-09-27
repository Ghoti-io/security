/**
 * @file
 *
 * libFuzzer harness for X25519.
 *
 * The same inputs agree twice. The public key is the base-point product.
 * An all-zero u-coordinate is rejected and the output is wiped.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/x25519.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char scalar[GSEC_X25519_LEN];
  unsigned char point[GSEC_X25519_LEN];
  unsigned char out[GSEC_X25519_LEN];
  unsigned char again[GSEC_X25519_LEN];
  unsigned char pub[GSEC_X25519_LEN];
  unsigned char base[GSEC_X25519_LEN];
  size_t i;
  GSEC_Result result;

  for (i = 0; i < sizeof scalar; i++) {
    scalar[i] = 0;
    point[i] = 0;
  }
  for (i = 0; i < sizeof scalar && i < size; i++) {
    scalar[i] = data[i];
  }
  for (i = 0; i < sizeof point && i < size; i++) {
    point[i] = data[size - 1u - i];
  }
  result = gsec_x25519(scalar, point, out);
  if (result != GSEC_OK && result != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  if (result == GSEC_ERR_INVALID) {
    for (i = 0; i < sizeof out; i++) {
      if (out[i] != 0) {
        __builtin_trap();
      }
    }
  } else if (gsec_x25519(scalar, point, again) != GSEC_OK ||
      gsec_equal(out, again, sizeof out) != GSEC_OK) {
    __builtin_trap();
  }
  for (i = 0; i < sizeof base; i++) {
    base[i] = 0;
  }
  base[0] = 9;
  if (gsec_x25519_public(scalar, pub) != GSEC_OK ||
      gsec_x25519(scalar, base, again) != GSEC_OK ||
      gsec_equal(pub, again, sizeof pub) != GSEC_OK) {
    __builtin_trap();
  }
  for (i = 0; i < sizeof point; i++) {
    point[i] = 0;
  }
  for (i = 0; i < sizeof out; i++) {
    out[i] = 0xa5;
  }
  if (gsec_x25519(scalar, point, out) != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  for (i = 0; i < sizeof out; i++) {
    if (out[i] != 0) {
      __builtin_trap();
    }
  }
  if (gsec_x25519(nullptr, point, out) != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  gsec_wipe(scalar, sizeof scalar);
  gsec_wipe(out, sizeof out);
  gsec_wipe(again, sizeof again);
  gsec_wipe(pub, sizeof pub);
  return 0;
}
