/**
 * @file
 *
 * libFuzzer harness for HKDF.
 *
 * Extract-then-expand and the combined call must agree. An output one byte
 * past 255 digests is a limit and must not be written.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/hkdf.h>
#include <ghoti.io/security/secret.h>

static uint32_t hash_of(uint8_t sel) {
  switch (sel & 3u) {
  case 0:
    return GSEC_HKDF_SHA1;
  case 1:
    return GSEC_HKDF_SHA256;
  case 2:
    return GSEC_HKDF_SHA384;
  default:
    return GSEC_HKDF_SHA512;
  }
}

static size_t digest_len(uint32_t hash) {
  if (hash == GSEC_HKDF_SHA1) {
    return GSEC_SHA1_DIGEST_LEN;
  }
  if (hash == GSEC_HKDF_SHA256) {
    return GSEC_SHA256_DIGEST_LEN;
  }
  if (hash == GSEC_HKDF_SHA384) {
    return GSEC_SHA384_DIGEST_LEN;
  }
  return GSEC_SHA512_DIGEST_LEN;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char prk[GSEC_SHA512_DIGEST_LEN];
  unsigned char expanded[GSEC_SHA512_DIGEST_LEN * 2u];
  unsigned char combined[GSEC_SHA512_DIGEST_LEN * 2u];
  uint32_t hash;
  size_t dig;
  size_t okm_len;
  const uint8_t * tail;
  const uint8_t * salt;
  const uint8_t * ikm;
  const uint8_t * info;
  size_t n;
  size_t salt_len;
  size_t ikm_len;
  size_t info_len;

  if (data == nullptr || size < 2) {
    if (gsec_hkdf(GSEC_HKDF_SHA256, nullptr, 0, nullptr, 0, nullptr, 0,
        combined, 16) != GSEC_OK) {
      __builtin_trap();
    }
    gsec_wipe(combined, 16);
    return 0;
  }
  hash = hash_of(data[0]);
  dig = digest_len(hash);
  okm_len = (size_t)(data[1] % (dig * 2u)) + 1u;
  tail = data + 2;
  n = size - 2;
  salt_len = n / 3u;
  ikm_len = n / 3u;
  info_len = n - salt_len - ikm_len;
  salt = tail;
  ikm = tail + salt_len;
  info = ikm + ikm_len;

  if (gsec_hkdf_extract(hash, salt_len == 0 ? nullptr : salt, salt_len,
      ikm_len == 0 ? nullptr : ikm, ikm_len, prk) != GSEC_OK ||
      gsec_hkdf_expand(hash, prk, dig, info_len == 0 ? nullptr : info,
      info_len, expanded, okm_len) != GSEC_OK ||
      gsec_hkdf(hash, salt_len == 0 ? nullptr : salt, salt_len,
      ikm_len == 0 ? nullptr : ikm, ikm_len,
      info_len == 0 ? nullptr : info, info_len, combined, okm_len) != GSEC_OK ||
      gsec_equal(expanded, combined, okm_len) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_hkdf_expand(hash, prk, dig, nullptr, 0, expanded,
      255u * dig + 1u) != GSEC_ERR_LIMIT) {
    __builtin_trap();
  }
  gsec_wipe(prk, sizeof prk);
  gsec_wipe(expanded, sizeof expanded);
  gsec_wipe(combined, sizeof combined);
  return 0;
}
