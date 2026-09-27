/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * Constant-time gate, clean plant.
 *
 * Built against the library compiled with GSEC_CT_TEST and run under
 * memcheck. A conditional jump on a poisoned byte here means gsec_equal or
 * gsec_wipe leaked. Refuses to run outside Valgrind: without it the poison
 * marks are invisible and a green exit would mean nothing.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/secret.h>

#include <string.h>
#include <valgrind/memcheck.h>

int main(void) {
  unsigned char a[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  unsigned char b[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  unsigned char secret[8];
  GSEC_Result result;
  size_t i;

  if (RUNNING_ON_VALGRIND == 0) {
    return 2;
  }

  gsec_poison(a, sizeof a);
  gsec_poison(b, sizeof b);
  result = gsec_equal(a, b, sizeof a);
  if (result != GSEC_OK) {
    return 3;
  }

  b[7] = 9;
  gsec_poison(b, sizeof b);
  result = gsec_equal(a, b, sizeof a);
  if (result != GSEC_ERR_MISMATCH) {
    return 4;
  }

  memset(secret, 0xA5, sizeof secret);
  gsec_poison(secret, sizeof secret);
  if (gsec_wipe(secret, sizeof secret) != GSEC_OK) {
    return 5;
  }
  for (i = 0; i < sizeof secret; i++) {
    if (secret[i] != 0) {
      return 6;
    }
  }
  return 0;
}
