/**
 * @file
 *
 * libFuzzer harness for AES-GCM.
 *
 * Encrypt then decrypt must return the plaintext. A flipped tag byte
 * is a mismatch, and the plaintext buffer is wiped. An empty nonce is
 * invalid.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/aes_gcm.h>
#include <ghoti.io/security/secret.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char key[GSEC_AES256_KEY_LEN];
  unsigned char iv[32];
  unsigned char aad[32];
  unsigned char pt[64];
  unsigned char ct[64];
  unsigned char back[64];
  unsigned char tag[16];
  size_t key_len = GSEC_AES128_KEY_LEN;
  size_t iv_len = 12;
  size_t aad_len;
  size_t pt_len;
  size_t tag_len = 16;
  size_t i;

  for (i = 0; i < sizeof key; i++) {
    key[i] = 0;
  }
  for (i = 0; i < sizeof iv; i++) {
    iv[i] = 0;
  }
  if (size > 0 && (data[0] & 1u) != 0) {
    key_len = GSEC_AES256_KEY_LEN;
  }
  if (size > 0 && (data[0] & 2u) != 0) {
    iv_len = 16;
  }
  if (size > 0 && (data[0] & 4u) != 0) {
    tag_len = 12;
  }
  aad_len = size > 8 ? (size_t)(data[1] % 17u) : 0;
  pt_len = size > 8 ? (size_t)(data[2] % 33u) : (size > 48 ? 48 : size);
  for (i = 0; i < key_len && i < size; i++) {
    key[i] = data[i];
  }
  for (i = 0; i < iv_len && i < size; i++) {
    iv[i] = data[size - 1u - i];
  }
  for (i = 0; i < aad_len && i < size; i++) {
    aad[i] = data[i];
  }
  for (i = 0; i < pt_len && i < size; i++) {
    pt[i] = data[i];
  }
  if (gsec_aes_gcm_encrypt(key, key_len, iv, iv_len, aad_len ? aad : nullptr,
          aad_len, pt_len ? pt : nullptr, pt_len, pt_len ? ct : nullptr, tag,
          tag_len) != GSEC_OK) {
    __builtin_trap();
  }
  for (i = 0; i < sizeof back; i++) {
    back[i] = 0xa5;
  }
  if (gsec_aes_gcm_decrypt(key, key_len, iv, iv_len, aad_len ? aad : nullptr,
          aad_len, pt_len ? ct : nullptr, pt_len, pt_len ? back : nullptr, tag,
          tag_len) != GSEC_OK) {
    __builtin_trap();
  }
  if (pt_len > 0 && gsec_equal(back, pt, pt_len) != GSEC_OK) {
    __builtin_trap();
  }
  tag[0] = static_cast<unsigned char>(tag[0] ^ 1u);
  for (i = 0; i < sizeof back; i++) {
    back[i] = 0xa5;
  }
  if (gsec_aes_gcm_decrypt(key, key_len, iv, iv_len, aad_len ? aad : nullptr,
          aad_len, pt_len ? ct : nullptr, pt_len, pt_len ? back : nullptr, tag,
          tag_len) != GSEC_ERR_MISMATCH) {
    __builtin_trap();
  }
  for (i = 0; i < pt_len; i++) {
    if (back[i] != 0) {
      __builtin_trap();
    }
  }
  if (gsec_aes_gcm_encrypt(key, key_len, iv, 0, nullptr, 0, pt, 1, ct, tag,
          16) != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  gsec_wipe(key, sizeof key);
  gsec_wipe(tag, sizeof tag);
  gsec_wipe(ct, sizeof ct);
  return 0;
}
