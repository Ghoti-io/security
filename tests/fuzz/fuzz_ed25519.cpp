/**
 * @file
 *
 * libFuzzer harness for Ed25519.
 *
 * The same seed and message sign twice to the same bytes, and that
 * signature verifies. A flipped signature byte does not. A null seed
 * is rejected.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/ed25519.h>
#include <ghoti.io/security/secret.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char seed[GSEC_ED25519_LEN];
  unsigned char sig[GSEC_ED25519_SIG_LEN];
  unsigned char again[GSEC_ED25519_SIG_LEN];
  unsigned char pub[GSEC_ED25519_LEN];
  const unsigned char * message = nullptr;
  size_t n = 0;
  size_t i;

  for (i = 0; i < sizeof seed; i++) {
    seed[i] = 0;
  }
  for (i = 0; i < sizeof seed && i < size; i++) {
    seed[i] = data[i];
  }
  if (size > sizeof seed) {
    message = data + sizeof seed;
    n = size - sizeof seed;
    if (n > 256u) {
      n = 256u;
    }
  }
  if (gsec_ed25519_sign(seed, message, n, sig) != GSEC_OK ||
      gsec_ed25519_sign(seed, message, n, again) != GSEC_OK ||
      gsec_equal(sig, again, sizeof sig) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_ed25519_public(seed, pub) != GSEC_OK ||
      gsec_ed25519_verify(pub, message, n, sig) != GSEC_OK) {
    __builtin_trap();
  }
  /* A flipped byte of R is a refusal, and which refusal depends on the byte:
   * GSEC_ERR_INVALID when the result is no longer a point on the curve or the
   * y coordinate is at or above the field prime, GSEC_ERR_MISMATCH when it is
   * a different valid point and the equation fails. Asserting MISMATCH alone
   * is what this harness did, and the EVO-X2 campaign trapped on the empty
   * input thirteen units in when the two were split apart. Both are refusals;
   * GSEC_OK is the only answer that must not happen. */
  sig[0] = static_cast<unsigned char>(sig[0] ^ 0x01u);
  {
    GSEC_Result flipped = gsec_ed25519_verify(pub, message, n, sig);

    if (flipped != GSEC_ERR_MISMATCH && flipped != GSEC_ERR_INVALID) {
      __builtin_trap();
    }
  }
  /* And S out of range is specifically the malformed-encoding answer. */
  sig[0] = static_cast<unsigned char>(sig[0] ^ 0x01u);
  sig[GSEC_ED25519_SIG_LEN - 1u] = 0xff;
  if (gsec_ed25519_verify(pub, message, n, sig) != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  if (gsec_ed25519_sign(nullptr, message, n, again) != GSEC_ERR_INVALID ||
      gsec_ed25519_verify(nullptr, message, n, again) != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  gsec_wipe(seed, sizeof seed);
  gsec_wipe(sig, sizeof sig);
  gsec_wipe(again, sizeof again);
  gsec_wipe(pub, sizeof pub);
  return 0;
}
