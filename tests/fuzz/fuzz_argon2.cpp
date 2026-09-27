/**
 * @file
 *
 * libFuzzer harness for Argon2id.
 *
 * The cost stays at the smallest legal parameters so a run finishes.
 * A salt shorter than eight bytes is invalid.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/argon2.h>
#include <ghoti.io/security/secret.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char password[16];
  unsigned char salt[8];
  unsigned char tag[16];
  size_t i;
  size_t n;

  for (i = 0; i < sizeof salt; i++) {
    salt[i] = 0;
  }
  for (i = 0; i < sizeof password; i++) {
    password[i] = 0;
  }
  n = size < sizeof password ? size : sizeof password;
  for (i = 0; i < n; i++) {
    password[i] = data[i];
  }
  for (i = 0; i < sizeof salt && n + i < size; i++) {
    salt[i] = data[n + i];
  }
  if (gsec_argon2(GSEC_ARGON2_ID, password, n, salt, sizeof salt, nullptr, 0,
          nullptr, 0, 8, 1, 1, tag, sizeof tag) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_argon2(GSEC_ARGON2_ID, password, n, salt, 7, nullptr, 0, nullptr, 0,
          8, 1, 1, tag, sizeof tag) != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  gsec_wipe(password, sizeof password);
  gsec_wipe(tag, sizeof tag);
  return 0;
}
