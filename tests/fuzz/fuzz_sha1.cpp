/**
 * @file
 *
 * libFuzzer harness for SHA-1.
 *
 * One-shot and two streaming cuts of the same bytes must agree.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/sha1.h>

static int same(const unsigned char * a, const unsigned char * b) {
  return gsec_equal(a, b, GSEC_SHA1_DIGEST_LEN) == GSEC_OK;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char one[GSEC_SHA1_DIGEST_LEN];
  unsigned char streamed[GSEC_SHA1_DIGEST_LEN];
  GSEC_Sha1 ctx;
  size_t cut;
  size_t i;

  if (gsec_sha1(size == 0 ? nullptr : data, size, one) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_sha1_init(&ctx) != GSEC_OK) {
    __builtin_trap();
  }
  cut = size == 0 ? 0 : (size_t)data[0];
  if (cut > size) {
    cut = size;
  }
  if (cut > 0 && gsec_sha1_update(&ctx, data, cut) != GSEC_OK) {
    __builtin_trap();
  }
  if (size > cut && gsec_sha1_update(&ctx, data + cut, size - cut) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_sha1_final(&ctx, streamed) != GSEC_OK || !same(one, streamed)) {
    __builtin_trap();
  }

  if (gsec_sha1_init(&ctx) != GSEC_OK) {
    __builtin_trap();
  }
  for (i = 0; i < size; i++) {
    if (gsec_sha1_update(&ctx, data + i, 1) != GSEC_OK) {
      __builtin_trap();
    }
  }
  if (gsec_sha1_final(&ctx, streamed) != GSEC_OK || !same(one, streamed)) {
    __builtin_trap();
  }
  gsec_wipe(one, sizeof one);
  gsec_wipe(streamed, sizeof streamed);
  return 0;
}
