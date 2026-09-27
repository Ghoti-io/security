/**
 * @file
 *
 * libFuzzer harness for AES-CTR.
 *
 * One-shot and a split update of the same bytes agree, in both
 * directions. A bad direction is invalid.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/aes_ctr.h>
#include <ghoti.io/security/secret.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char key[GSEC_AES256_KEY_LEN];
  unsigned char counter[GSEC_AES_BLOCK_LEN];
  unsigned char one[256];
  unsigned char sliced[256];
  GSEC_Aes_Ctr ctx;
  size_t key_len = GSEC_AES128_KEY_LEN;
  uint32_t direction = GSEC_AES_CTR_BE;
  size_t n;
  size_t cut;
  size_t i;

  for (i = 0; i < sizeof key; i++) {
    key[i] = 0;
  }
  for (i = 0; i < sizeof counter; i++) {
    counter[i] = 0;
  }
  n = size > 64 ? 64 : size;
  if (size > 0 && (data[0] & 1u) != 0) {
    direction = GSEC_AES_CTR_LE;
  }
  if (size > 0 && (data[0] & 2u) != 0) {
    key_len = GSEC_AES256_KEY_LEN;
  }
  for (i = 0; i < n && i < sizeof key; i++) {
    key[i] = data[i];
  }
  for (i = 0; i < sizeof counter && i < size; i++) {
    counter[i] = data[size - 1u - i];
  }
  if (gsec_aes_ctr(key, key_len, counter, direction, n == 0 ? nullptr : data,
          one, n) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_aes_ctr_init(&ctx, key, key_len, counter, direction) != GSEC_OK) {
    __builtin_trap();
  }
  cut = n == 0 ? 0 : (size_t)(data[0] % (n + 1u));
  if (cut > 0 && gsec_aes_ctr_update(&ctx, data, sliced, cut) != GSEC_OK) {
    __builtin_trap();
  }
  if (n > cut &&
      gsec_aes_ctr_update(&ctx, data + cut, sliced + cut, n - cut) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_aes_ctr_wipe(&ctx) != GSEC_OK ||
      (n > 0 && gsec_equal(one, sliced, n) != GSEC_OK)) {
    __builtin_trap();
  }
  if (gsec_aes_ctr(key, key_len, counter, 0, data, one, n == 0 ? 1 : n) !=
      GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  gsec_wipe(key, sizeof key);
  gsec_wipe(one, sizeof one);
  gsec_wipe(sliced, sizeof sliced);
  return 0;
}
