/**
 * @file
 *
 * libFuzzer harness for SHA-512 and SHA-384.
 *
 * One-shot and two streaming cuts of the same bytes must agree. A
 * disagreement is a padding or length bug. An over-read is an ASan report.
 * The two hashes are not compared with each other: SHA-384 is not a
 * truncation of SHA-512.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/sha384.h>
#include <ghoti.io/security/sha512.h>

static int same(const unsigned char * a, const unsigned char * b, size_t n) {
  return gsec_equal(a, b, n) == GSEC_OK;
}

static void check_sha512(const uint8_t * data, size_t size) {
  unsigned char one[GSEC_SHA512_DIGEST_LEN];
  unsigned char streamed[GSEC_SHA512_DIGEST_LEN];
  GSEC_Sha512 ctx;
  size_t cut;
  size_t i;

  if (gsec_sha512(size == 0 ? nullptr : data, size, one) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_sha512_init(&ctx) != GSEC_OK) {
    __builtin_trap();
  }
  cut = size == 0 ? 0 : (size_t)data[0];
  if (cut > size) {
    cut = size;
  }
  if (cut > 0 && gsec_sha512_update(&ctx, data, cut) != GSEC_OK) {
    __builtin_trap();
  }
  if (size > cut && gsec_sha512_update(&ctx, data + cut, size - cut) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_sha512_final(&ctx, streamed) != GSEC_OK ||
      !same(one, streamed, sizeof one)) {
    __builtin_trap();
  }

  if (gsec_sha512_init(&ctx) != GSEC_OK) {
    __builtin_trap();
  }
  for (i = 0; i < size; i++) {
    if (gsec_sha512_update(&ctx, data + i, 1) != GSEC_OK) {
      __builtin_trap();
    }
  }
  if (gsec_sha512_final(&ctx, streamed) != GSEC_OK ||
      !same(one, streamed, sizeof one)) {
    __builtin_trap();
  }
  gsec_wipe(one, sizeof one);
  gsec_wipe(streamed, sizeof streamed);
}

static void check_sha384(const uint8_t * data, size_t size) {
  unsigned char one[GSEC_SHA384_DIGEST_LEN];
  unsigned char streamed[GSEC_SHA384_DIGEST_LEN];
  GSEC_Sha384 ctx;
  size_t cut;
  size_t i;

  if (gsec_sha384(size == 0 ? nullptr : data, size, one) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_sha384_init(&ctx) != GSEC_OK) {
    __builtin_trap();
  }
  cut = size == 0 ? 0 : (size_t)data[0];
  if (cut > size) {
    cut = size;
  }
  if (cut > 0 && gsec_sha384_update(&ctx, data, cut) != GSEC_OK) {
    __builtin_trap();
  }
  if (size > cut && gsec_sha384_update(&ctx, data + cut, size - cut) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_sha384_final(&ctx, streamed) != GSEC_OK ||
      !same(one, streamed, sizeof one)) {
    __builtin_trap();
  }

  if (gsec_sha384_init(&ctx) != GSEC_OK) {
    __builtin_trap();
  }
  for (i = 0; i < size; i++) {
    if (gsec_sha384_update(&ctx, data + i, 1) != GSEC_OK) {
      __builtin_trap();
    }
  }
  if (gsec_sha384_final(&ctx, streamed) != GSEC_OK ||
      !same(one, streamed, sizeof one)) {
    __builtin_trap();
  }
  gsec_wipe(one, sizeof one);
  gsec_wipe(streamed, sizeof streamed);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  check_sha512(data, size);
  check_sha384(data, size);
  return 0;
}
