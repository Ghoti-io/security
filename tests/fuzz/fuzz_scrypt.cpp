/**
 * @file
 *
 * libFuzzer harness for scrypt.
 *
 * The cost stays at the RFC's smallest parameters so a run finishes.
 * A parameter that is not a power of two is invalid.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/scrypt.h>
#include <ghoti.io/security/secret.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char password[16];
  unsigned char salt[16];
  unsigned char dk[16];
  size_t i;
  GSEC_Result result;

  for (i = 0; i < sizeof password; i++) {
    password[i] = 0;
    salt[i] = 0;
  }
  for (i = 0; i < size && i < sizeof password; i++) {
    password[i] = data[i];
  }
  for (; i < size && i < sizeof password + sizeof salt; i++) {
    salt[i - sizeof password] = data[i];
  }
  result = gsec_scrypt(password, sizeof password, salt, sizeof salt, 16, 1, 1,
      dk, sizeof dk);
  if (result != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_scrypt(password, sizeof password, salt, sizeof salt, 3, 1, 1, dk,
          sizeof dk) != GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  gsec_wipe(password, sizeof password);
  gsec_wipe(dk, sizeof dk);
  return 0;
}
