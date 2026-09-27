/**
 * @file
 *
 * libFuzzer harness for PBKDF2.
 *
 * Two derivations of the same input must agree. The iteration count is
 * taken from the low bits of one byte so a run stays short. Zero iterations
 * are invalid.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/pbkdf2.h>
#include <ghoti.io/security/secret.h>

static uint32_t hash_of(uint8_t sel) {
  switch (sel & 3u) {
  case 0:
    return GSEC_PBKDF2_SHA1;
  case 1:
    return GSEC_PBKDF2_SHA256;
  case 2:
    return GSEC_PBKDF2_SHA384;
  default:
    return GSEC_PBKDF2_SHA512;
  }
}

static size_t digest_len(uint32_t hash) {
  if (hash == GSEC_PBKDF2_SHA1) {
    return GSEC_SHA1_DIGEST_LEN;
  }
  if (hash == GSEC_PBKDF2_SHA256) {
    return GSEC_SHA256_DIGEST_LEN;
  }
  if (hash == GSEC_PBKDF2_SHA384) {
    return GSEC_SHA384_DIGEST_LEN;
  }
  return GSEC_SHA512_DIGEST_LEN;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char a[GSEC_SHA512_DIGEST_LEN];
  unsigned char b[GSEC_SHA512_DIGEST_LEN];
  uint32_t hash;
  uint32_t iterations;
  size_t dig;
  size_t dk_len;
  size_t password_len;
  size_t salt_len;
  const uint8_t * password;
  const uint8_t * salt;

  if (data == nullptr || size < 2) {
    if (gsec_pbkdf2(GSEC_PBKDF2_SHA1, nullptr, 0, nullptr, 0, 1, a, 16) !=
        GSEC_OK) {
      __builtin_trap();
    }
    gsec_wipe(a, sizeof a);
    return 0;
  }
  hash = hash_of(data[0]);
  dig = digest_len(hash);
  iterations = (uint32_t)(data[1] & 3u) + 1u;
  dk_len = (size_t)((data[1] >> 2) % dig) + 1u;
  password_len = size > 2 ? (size - 2) / 2 : 0;
  salt_len = size > 2 ? (size - 2) - password_len : 0;
  password = data + 2;
  salt = password + password_len;
  if (gsec_pbkdf2(hash, password_len == 0 ? nullptr : password, password_len,
      salt_len == 0 ? nullptr : salt, salt_len, iterations, a, dk_len) !=
      GSEC_OK ||
      gsec_pbkdf2(hash, password_len == 0 ? nullptr : password, password_len,
      salt_len == 0 ? nullptr : salt, salt_len, iterations, b, dk_len) !=
      GSEC_OK ||
      gsec_equal(a, b, dk_len) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_pbkdf2(hash, password_len == 0 ? nullptr : password, password_len,
      salt_len == 0 ? nullptr : salt, salt_len, 0, a, dk_len) !=
      GSEC_ERR_INVALID) {
    __builtin_trap();
  }
  gsec_wipe(a, sizeof a);
  gsec_wipe(b, sizeof b);
  return 0;
}
