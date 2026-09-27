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
#include <ghoti.io/security/hkdf.h>
#include <ghoti.io/security/hmac.h>
#include <ghoti.io/security/sha1.h>
#include <ghoti.io/security/sha256.h>
#include <ghoti.io/security/sha384.h>
#include <ghoti.io/security/sha512.h>

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

  /* The message is secret. A branch or a table index on one of its bytes
   * inside SHA-256 is the leak this run exists to report. The digest is a
   * function of that message, so it is wiped rather than inspected. */
  {
    unsigned char digest[GSEC_SHA256_DIGEST_LEN];

    gsec_poison(secret, sizeof secret);
    if (gsec_sha256(secret, sizeof secret, digest) != GSEC_OK) {
      return 7;
    }
    gsec_wipe(digest, sizeof digest);
  }
  {
    unsigned char digest[GSEC_SHA512_DIGEST_LEN];

    gsec_poison(secret, sizeof secret);
    if (gsec_sha512(secret, sizeof secret, digest) != GSEC_OK) {
      return 8;
    }
    gsec_wipe(digest, sizeof digest);
  }
  {
    unsigned char digest[GSEC_SHA384_DIGEST_LEN];

    gsec_poison(secret, sizeof secret);
    if (gsec_sha384(secret, sizeof secret, digest) != GSEC_OK) {
      return 9;
    }
    gsec_wipe(digest, sizeof digest);
  }
  {
    unsigned char digest[GSEC_SHA1_DIGEST_LEN];

    gsec_poison(secret, sizeof secret);
    if (gsec_sha1(secret, sizeof secret, digest) != GSEC_OK) {
      return 10;
    }
    gsec_wipe(digest, sizeof digest);
  }
  {
    unsigned char mac[GSEC_SHA256_DIGEST_LEN];
    unsigned char key[8];

    memset(key, 0x3c, sizeof key);
    gsec_poison(key, sizeof key);
    gsec_poison(secret, sizeof secret);
    if (gsec_hmac(GSEC_HMAC_SHA256, key, sizeof key, secret, sizeof secret,
        mac) != GSEC_OK) {
      return 11;
    }
    gsec_wipe(mac, sizeof mac);
    gsec_wipe(key, sizeof key);
  }
  {
    unsigned char okm[16];

    gsec_poison(secret, sizeof secret);
    if (gsec_hkdf(GSEC_HKDF_SHA256, NULL, 0, secret, sizeof secret, NULL, 0,
        okm, sizeof okm) != GSEC_OK) {
      return 12;
    }
    gsec_wipe(okm, sizeof okm);
  }
  return 0;
}
