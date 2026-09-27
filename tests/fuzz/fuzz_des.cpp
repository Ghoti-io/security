/**
 * @file
 *
 * libFuzzer harness for DES and Triple DES.
 *
 * Encrypt then decrypt returns the block. A bad length is invalid.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/des.h>
#include <ghoti.io/security/secret.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char key[GSEC_DES_EDE3_KEY_LEN];
  unsigned char iv[GSEC_DES_BLOCK_LEN];
  unsigned char block[GSEC_DES_BLOCK_LEN];
  unsigned char ct[GSEC_DES_BLOCK_LEN];
  unsigned char back[GSEC_DES_BLOCK_LEN];
  size_t i;
  size_t n;

  for (i = 0; i < sizeof key; i++) {
    key[i] = 0;
  }
  for (i = 0; i < sizeof iv; i++) {
    iv[i] = 0;
    block[i] = 0;
  }
  n = size < sizeof key + sizeof block ? size : sizeof key + sizeof block;
  for (i = 0; i < n && i < sizeof key; i++) {
    key[i] = data[i];
  }
  for (; i < n; i++) {
    block[i - sizeof key] = data[i];
  }
  if (gsec_des_encrypt(key, block, ct) != GSEC_OK ||
      gsec_des_decrypt(key, ct, back) != GSEC_OK ||
      gsec_equal(back, block, sizeof block) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_des_ede3_encrypt(key, block, ct) != GSEC_OK ||
      gsec_des_ede3_decrypt(key, ct, back) != GSEC_OK ||
      gsec_equal(back, block, sizeof block) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_des_cbc_encrypt(key, iv, block, sizeof block, ct) != GSEC_OK ||
      gsec_des_cbc_decrypt(key, iv, ct, sizeof ct, back) != GSEC_OK ||
      gsec_equal(back, block, sizeof block) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_des_encrypt(nullptr, block, ct) != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  gsec_wipe(key, sizeof key);
  gsec_wipe(ct, sizeof ct);
  return 0;
}
