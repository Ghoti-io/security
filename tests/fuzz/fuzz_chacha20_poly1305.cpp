/**
 * @file
 *
 * libFuzzer harness for ChaCha20-Poly1305.
 *
 * Encrypt then decrypt must return the plaintext. A flipped tag byte
 * is a mismatch, and the plaintext buffer is wiped.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/chacha20_poly1305.h>
#include <ghoti.io/security/secret.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char key[GSEC_CHACHA20_KEY_LEN];
  unsigned char nonce[GSEC_CHACHA20_NONCE_LEN];
  unsigned char aad[32];
  unsigned char pt[64];
  unsigned char ct[64];
  unsigned char back[64];
  unsigned char tag[GSEC_POLY1305_TAG_LEN];
  size_t aad_len = 0;
  size_t pt_len = 0;
  size_t i;

  for (i = 0; i < sizeof key; i++) {
    key[i] = 0;
  }
  for (i = 0; i < sizeof nonce; i++) {
    nonce[i] = 0;
  }
  if (size > 8) {
    aad_len = (size_t)(data[0] % 17u);
    pt_len = (size_t)(data[1] % 33u);
  }
  for (i = 0; i < sizeof key && i < size; i++) {
    key[i] = data[i];
  }
  for (i = 0; i < sizeof nonce && i < size; i++) {
    nonce[i] = data[size - 1u - i];
  }
  for (i = 0; i < aad_len && i < size; i++) {
    aad[i] = data[i];
  }
  for (i = 0; i < pt_len && i < size; i++) {
    pt[i] = data[i];
  }
  if (gsec_chacha20_poly1305_encrypt(key, nonce, aad_len ? aad : nullptr,
          aad_len, pt_len ? pt : nullptr, pt_len, pt_len ? ct : nullptr,
          tag) != GSEC_OK) {
    __builtin_trap();
  }
  for (i = 0; i < sizeof back; i++) {
    back[i] = 0xa5;
  }
  if (gsec_chacha20_poly1305_decrypt(key, nonce, aad_len ? aad : nullptr,
          aad_len, pt_len ? ct : nullptr, pt_len, pt_len ? back : nullptr,
          tag) != GSEC_OK) {
    __builtin_trap();
  }
  if (pt_len > 0 && gsec_equal(back, pt, pt_len) != GSEC_OK) {
    __builtin_trap();
  }
  tag[0] = static_cast<unsigned char>(tag[0] ^ 1u);
  for (i = 0; i < sizeof back; i++) {
    back[i] = 0xa5;
  }
  if (gsec_chacha20_poly1305_decrypt(key, nonce, aad_len ? aad : nullptr,
          aad_len, pt_len ? ct : nullptr, pt_len, pt_len ? back : nullptr,
          tag) != GSEC_ERR_MISMATCH) {
    __builtin_trap();
  }
  for (i = 0; i < pt_len; i++) {
    if (back[i] != 0) {
      __builtin_trap();
    }
  }
  if (gsec_chacha20_poly1305_encrypt(nullptr, nonce, nullptr, 0, pt, 1, ct,
          tag) != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  gsec_wipe(key, sizeof key);
  gsec_wipe(tag, sizeof tag);
  return 0;
}
