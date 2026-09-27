/**
 * @file
 *
 * libFuzzer harness for AES-CBC.
 *
 * Encrypt then decrypt returns the plaintext. A length that is not a
 * multiple of the block is invalid.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/aes_cbc.h>
#include <ghoti.io/security/secret.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char key[GSEC_AES256_KEY_LEN];
  unsigned char iv[GSEC_AES_BLOCK_LEN];
  unsigned char pt[64];
  unsigned char ct[64];
  unsigned char back[64];
  size_t key_len;
  size_t len;
  size_t i;
  size_t n;

  for (i = 0; i < sizeof key; i++) {
    key[i] = 0;
  }
  for (i = 0; i < sizeof iv; i++) {
    iv[i] = 0;
  }
  for (i = 0; i < sizeof pt; i++) {
    pt[i] = 0;
  }
  n = size;
  if (n > sizeof key + sizeof iv + sizeof pt) {
    n = sizeof key + sizeof iv + sizeof pt;
  }
  for (i = 0; i < n && i < sizeof key; i++) {
    key[i] = data[i];
  }
  for (; i < n && i < sizeof key + sizeof iv; i++) {
    iv[i - sizeof key] = data[i];
  }
  for (; i < n; i++) {
    pt[i - sizeof key - sizeof iv] = data[i];
  }
  key_len = GSEC_AES128_KEY_LEN;
  if (size > 0 && (data[0] % 3u) == 1u) {
    key_len = GSEC_AES192_KEY_LEN;
  } else if (size > 0 && (data[0] % 3u) == 2u) {
    key_len = GSEC_AES256_KEY_LEN;
  }
  len = size > 0 ? (size_t)(data[0] % 5u) * GSEC_AES_BLOCK_LEN : 0;
  if (len > sizeof pt) {
    len = sizeof pt;
  }
  if (gsec_aes_cbc_encrypt(key, key_len, iv, len == 0 ? nullptr : pt, len,
          len == 0 ? nullptr : ct) != GSEC_OK ||
      gsec_aes_cbc_decrypt(key, key_len, iv, len == 0 ? nullptr : ct, len,
          len == 0 ? nullptr : back) != GSEC_OK) {
    __builtin_trap();
  }
  if (len != 0 && gsec_equal(back, pt, len) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_aes_cbc_encrypt(key, 15, iv, pt, 16, ct) != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  gsec_wipe(key, sizeof key);
  gsec_wipe(ct, sizeof ct);
  gsec_wipe(back, sizeof back);
  return 0;
}
