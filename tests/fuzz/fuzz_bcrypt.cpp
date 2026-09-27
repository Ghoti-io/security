/**
 * @file
 *
 * libFuzzer harness for bcrypt.
 *
 * The cost stays at the minimum so a run finishes. A cost below that
 * minimum is invalid.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/bcrypt.h>
#include <ghoti.io/security/secret.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char password[16];
  unsigned char salt[16];
  unsigned char hash[24];
  size_t i;
  size_t n;

  for (i = 0; i < sizeof password; i++) {
    password[i] = 0;
    salt[i] = 0;
  }
  n = size < sizeof password ? size : sizeof password;
  for (i = 0; i < n; i++) {
    password[i] = data[i];
  }
  for (; i < size && i < sizeof password + sizeof salt; i++) {
    salt[i - sizeof password] = data[i];
  }
  if (gsec_bcrypt(password, n, salt, sizeof salt, 4, hash, sizeof hash)
      != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_bcrypt(password, n, salt, sizeof salt, 3, hash, sizeof hash)
      != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  gsec_wipe(password, sizeof password);
  gsec_wipe(hash, sizeof hash);
  return 0;
}
