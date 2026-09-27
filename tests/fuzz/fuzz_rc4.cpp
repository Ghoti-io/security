/**
 * @file
 *
 * libFuzzer harness for RC4.
 *
 * Encrypting twice returns the input. A key longer than 256 bytes is
 * invalid.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/rc4.h>
#include <ghoti.io/security/secret.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char key[GSEC_RC4_KEY_MAX];
  unsigned char msg[64];
  unsigned char ct[64];
  unsigned char back[64];
  size_t key_len;
  size_t msg_len;
  size_t i;

  if (size == 0) {
    if (gsec_rc4(key, 0, msg, 0, msg) != GSEC_ERR_INVALID) {
      __builtin_trap();
    }
    return 0;
  }
  key_len = (size_t)(data[0] % 32u) + 1u;
  if (key_len > size) {
    key_len = size;
  }
  for (i = 0; i < key_len; i++) {
    key[i] = data[i % size];
  }
  msg_len = size < sizeof msg ? size : sizeof msg;
  for (i = 0; i < msg_len; i++) {
    msg[i] = data[i];
  }
  if (gsec_rc4(key, key_len, msg, msg_len, ct) != GSEC_OK ||
      gsec_rc4(key, key_len, ct, msg_len, back) != GSEC_OK ||
      gsec_equal(back, msg, msg_len) != GSEC_OK) {
    __builtin_trap();
  }
  gsec_wipe(key, key_len);
  gsec_wipe(ct, sizeof ct);
  return 0;
}
