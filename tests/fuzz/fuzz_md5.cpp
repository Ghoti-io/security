/**
 * @file
 *
 * libFuzzer harness for MD5.
 *
 * One-shot and two streaming cuts of the same bytes must agree.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/security/md5.h>
#include <ghoti.io/security/secret.h>

static int same(const unsigned char * a, const unsigned char * b) {
  return gsec_equal(a, b, GSEC_MD5_DIGEST_LEN) == GSEC_OK;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char one[GSEC_MD5_DIGEST_LEN];
  unsigned char streamed[GSEC_MD5_DIGEST_LEN];
  GSEC_Md5 ctx;
  size_t cut;
  size_t i;

  if (gsec_md5(size == 0 ? nullptr : data, size, one) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_md5_init(&ctx) != GSEC_OK) {
    __builtin_trap();
  }
  cut = size == 0 ? 0 : (size_t)data[0];
  if (cut > size) {
    cut = size;
  }
  if (cut > 0 && gsec_md5_update(&ctx, data, cut) != GSEC_OK) {
    __builtin_trap();
  }
  if (size > cut && gsec_md5_update(&ctx, data + cut, size - cut) != GSEC_OK) {
    __builtin_trap();
  }
  if (gsec_md5_final(&ctx, streamed) != GSEC_OK || !same(one, streamed)) {
    __builtin_trap();
  }

  if (gsec_md5_init(&ctx) != GSEC_OK) {
    __builtin_trap();
  }
  for (i = 0; i < size; i++) {
    if (gsec_md5_update(&ctx, data + i, 1) != GSEC_OK) {
      __builtin_trap();
    }
  }
  if (gsec_md5_final(&ctx, streamed) != GSEC_OK || !same(one, streamed)) {
    __builtin_trap();
  }
  gsec_wipe(one, sizeof one);
  gsec_wipe(streamed, sizeof streamed);
  return 0;
}
