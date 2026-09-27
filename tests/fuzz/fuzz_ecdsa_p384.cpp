/**
 * @file
 *
 * libFuzzer harness for ECDSA P-384.
 *
 * A scalar in range signs, and that signature verifies. A scalar that is
 * not in range is rejected and the signature is wiped. A signature taken
 * from the input is either accepted or rejected, and does not crash.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/ecdsa_p384.h>
#include <ghoti.io/security/secret.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char scalar[GSEC_ECDSA_P384_LEN];
  unsigned char pub[GSEC_ECDSA_P384_PUBLIC_LEN];
  unsigned char sig[GSEC_ECDSA_P384_SIG_LEN];
  unsigned char guess[GSEC_ECDSA_P384_SIG_LEN];
  size_t i;
  size_t msg_len;
  GSEC_Result result;
  GSEC_Result verified;

  for (i = 0; i < sizeof scalar; i++) {
    scalar[i] = 0;
  }
  for (i = 0; i < sizeof guess; i++) {
    guess[i] = 0;
  }
  for (i = 0; i < sizeof scalar && i < size; i++) {
    scalar[i] = data[i];
  }
  msg_len = 0;
  if (size > sizeof scalar) {
    msg_len = size - sizeof scalar;
    if (msg_len > 64) {
      msg_len = 64;
    }
  }
  for (i = 0; i < sizeof guess && sizeof scalar + msg_len + i < size; i++) {
    guess[i] = data[sizeof scalar + msg_len + i];
  }
  result = gsec_ecdsa_p384_sign(scalar,
      msg_len == 0 ? nullptr : data + sizeof scalar, msg_len, sig);
  if (result != GSEC_OK && result != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  if (result == GSEC_ERR_INVALID) {
    for (i = 0; i < sizeof sig; i++) {
      if (sig[i] != 0) {
        __builtin_trap();
      }
    }
    for (i = 0; i < sizeof pub; i++) {
      pub[i] = 0;
    }
  } else {
    if (gsec_ecdsa_p384_public(scalar, pub) != GSEC_OK) {
      __builtin_trap();
    }
    if (gsec_ecdsa_p384_verify(pub,
        msg_len == 0 ? nullptr : data + sizeof scalar, msg_len, sig) !=
        GSEC_OK) {
      __builtin_trap();
    }
  }
  verified = gsec_ecdsa_p384_verify(pub,
      msg_len == 0 ? nullptr : data + sizeof scalar, msg_len, guess);
  if (verified != GSEC_OK && verified != GSEC_ERR_MISMATCH) {
    __builtin_trap();
  }
  if (gsec_ecdsa_p384_sign(nullptr, nullptr, 0, sig) != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  gsec_wipe(scalar, sizeof scalar);
  gsec_wipe(pub, sizeof pub);
  gsec_wipe(sig, sizeof sig);
  gsec_wipe(guess, sizeof guess);
  return 0;
}
