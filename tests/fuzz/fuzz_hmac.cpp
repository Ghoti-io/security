/**
 * @file
 *
 * libFuzzer harness for HMAC.
 *
 * One-shot and a streaming cut of the same key and message must agree,
 * for whichever of the four hashes the first byte selects. Verify accepts
 * that MAC and rejects a flipped byte.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/hmac.h>
#include <ghoti.io/security/secret.h>

static uint32_t hash_of(uint8_t sel) {
  switch (sel & 3u) {
  case 0:
    return GSEC_HMAC_SHA1;
  case 1:
    return GSEC_HMAC_SHA256;
  case 2:
    return GSEC_HMAC_SHA384;
  default:
    return GSEC_HMAC_SHA512;
  }
}

static size_t digest_len(uint32_t hash) {
  if (hash == GSEC_HMAC_SHA1) {
    return GSEC_SHA1_DIGEST_LEN;
  }
  if (hash == GSEC_HMAC_SHA256) {
    return GSEC_SHA256_DIGEST_LEN;
  }
  if (hash == GSEC_HMAC_SHA384) {
    return GSEC_SHA384_DIGEST_LEN;
  }
  return GSEC_SHA512_DIGEST_LEN;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char one[GSEC_SHA512_DIGEST_LEN];
  unsigned char streamed[GSEC_SHA512_DIGEST_LEN];
  GSEC_Hmac ctx;
  uint32_t hash;
  size_t dig;
  size_t key_len;
  size_t cut;
  const uint8_t * key;
  const uint8_t * msg;
  size_t msg_len;

  if (data == nullptr || size < 2) {
    if (gsec_hmac(GSEC_HMAC_SHA256, nullptr, 0, nullptr, 0, one) != GSEC_OK) {
      __builtin_trap();
    }
    gsec_wipe(one, sizeof one);
    return 0;
  }
  hash = hash_of(data[0]);
  dig = digest_len(hash);
  key_len = data[1];
  if (key_len > size - 2) {
    key_len = size - 2;
  }
  key = data + 2;
  msg = key + key_len;
  msg_len = size - 2 - key_len;

  if (gsec_hmac(hash, key_len == 0 ? nullptr : key, key_len,
      msg_len == 0 ? nullptr : msg, msg_len, one) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_hmac_init(&ctx, hash, key_len == 0 ? nullptr : key, key_len) !=
      GSEC_OK) {
    __builtin_trap();
  }
  cut = msg_len == 0 ? 0 : (size_t)msg[0];
  if (cut > msg_len) {
    cut = msg_len;
  }
  if (cut > 0 && gsec_hmac_update(&ctx, msg, cut) != GSEC_OK) {
    __builtin_trap();
  }
  if (msg_len > cut && gsec_hmac_update(&ctx, msg + cut, msg_len - cut) !=
      GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_hmac_final(&ctx, streamed) != GSEC_OK ||
      gsec_equal(one, streamed, dig) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_hmac_verify(hash, key_len == 0 ? nullptr : key, key_len,
      msg_len == 0 ? nullptr : msg, msg_len, one, dig) != GSEC_OK) {
    __builtin_trap();
  }
  one[0] = static_cast<unsigned char>(one[0] ^ 0x01u);
  if (gsec_hmac_verify(hash, key_len == 0 ? nullptr : key, key_len,
      msg_len == 0 ? nullptr : msg, msg_len, one, dig) != GSEC_ERR_MISMATCH) {
    __builtin_trap();
  }
  gsec_wipe(one, sizeof one);
  gsec_wipe(streamed, sizeof streamed);
  return 0;
}
