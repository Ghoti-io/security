/**
 * @file
 *
 * libFuzzer harness for AES.
 *
 * Encrypt then decrypt returns the block. A key length that is not 16,
 * 24, or 32 is invalid and writes nothing.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/aes.h>
#include <ghoti.io/security/secret.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char key[GSEC_AES256_KEY_LEN];
  unsigned char block[GSEC_AES_BLOCK_LEN];
  unsigned char ct[GSEC_AES_BLOCK_LEN];
  unsigned char back[GSEC_AES_BLOCK_LEN];
  unsigned char sentinel = 0xa5;
  size_t key_len;
  size_t i;
  size_t n;

  for (i = 0; i < sizeof key; i++) {
    key[i] = 0;
  }
  for (i = 0; i < sizeof block; i++) {
    block[i] = 0;
  }
  n = size;
  if (n > sizeof key + sizeof block) {
    n = sizeof key + sizeof block;
  }
  for (i = 0; i < n && i < sizeof key; i++) {
    key[i] = data[i];
  }
  for (; i < n; i++) {
    block[i - sizeof key] = data[i];
  }

  key_len = GSEC_AES128_KEY_LEN;
  if (size > 0) {
    unsigned sel = data[0] % 3u;
    if (sel == 1u) {
      key_len = GSEC_AES192_KEY_LEN;
    } else if (sel == 2u) {
      key_len = GSEC_AES256_KEY_LEN;
    }
  }
  if (gsec_aes_encrypt(key, key_len, block, ct) != GSEC_OK ||
      gsec_aes_decrypt(key, key_len, ct, back) != GSEC_OK ||
      gsec_equal(back, block, sizeof block) != GSEC_OK) {
    __builtin_trap();
  }

  ct[0] = sentinel;
  if (gsec_aes_encrypt(key, 15, block, ct) != GSEC_ERR_INVALID ||
      ct[0] != sentinel) {
    __builtin_trap();
  }
  gsec_wipe(key, sizeof key);
  gsec_wipe(block, sizeof block);
  gsec_wipe(ct, sizeof ct);
  gsec_wipe(back, sizeof back);
  return 0;
}
