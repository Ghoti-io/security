/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * This file is part of Ghoti.io Security.
 *
 * Ghoti.io Security is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * Ghoti.io Security is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file
 *
 * Known answers an embedder can run without the test suite.
 *
 * The bytes below are not secret. They are fixed inputs, and nothing here
 * writes them anywhere except into stack buffers that are wiped before return.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/random.h>
#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/selftest.h>
#include <ghoti.io/security/sha256.h>

GSEC_Result gsec_selftest(void) {
  static const unsigned char left[4] = {0x00, 0x01, 0x02, 0x03};
  static const unsigned char right[4] = {0x00, 0x01, 0x02, 0x04};
  unsigned char buffer[32];
  unsigned char drawn[32];
  size_t i;
  GSEC_Result result;
  unsigned char changed;

  result = gsec_equal(NULL, NULL, 0);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_equal(left, left, sizeof left);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_equal(left, right, sizeof left);
  if (result != GSEC_ERR_MISMATCH) {
    return result == GSEC_OK ? GSEC_ERR_INTERNAL : result;
  }

  for (i = 0; i < sizeof buffer; i++) {
    buffer[i] = 0xA5;
  }
  result = gsec_wipe(buffer, sizeof buffer);
  if (result != GSEC_OK) {
    return result;
  }
  for (i = 0; i < sizeof buffer; i++) {
    if (buffer[i] != 0) {
      return GSEC_ERR_INTERNAL;
    }
  }

  for (i = 0; i < sizeof drawn; i++) {
    drawn[i] = 0xA5;
  }
  result = gsec_random_bytes(drawn, sizeof drawn, NULL);
  if (result != GSEC_OK) {
    return result;
  }
  /* 32 bytes of 0xA5 from the kernel is a possible output. It is not a
   * plausible one, and a generator that failed to write would leave exactly
   * that pattern. Every byte is folded in: stopping at the first difference
   * would be the timing leak this library exists not to write, and the bytes
   * are key material until the wipe below. */
  changed = 0;
  for (i = 0; i < sizeof drawn; i++) {
    changed = (unsigned char)(changed | (unsigned char)(drawn[i] ^ 0xA5));
  }
  result = gsec_wipe(drawn, sizeof drawn);
  if (result != GSEC_OK) {
    return result;
  }
  if (changed == 0) {
    return GSEC_ERR_INTERNAL;
  }

  /* RFC 6234 section 8.1. Empty, and "abc" absorbed one byte at a time,
   * which is the padding boundary the one-shot call does not exercise. */
  {
    static const unsigned char empty_dig[GSEC_SHA256_DIGEST_LEN] = {
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,
      0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
      0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    static const unsigned char abc_dig[GSEC_SHA256_DIGEST_LEN] = {
      0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
      0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
      0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    static const unsigned char abc_msg[3] = {0x61, 0x62, 0x63};
    unsigned char dig[GSEC_SHA256_DIGEST_LEN];
    GSEC_Sha256 ctx;

    result = gsec_sha256(NULL, 0, dig);
    if (result != GSEC_OK) {
      return result;
    }
    result = gsec_equal(dig, empty_dig, sizeof dig);
    gsec_wipe(dig, sizeof dig);
    if (result != GSEC_OK) {
      return result == GSEC_ERR_MISMATCH ? GSEC_ERR_INTERNAL : result;
    }

    result = gsec_sha256_init(&ctx);
    if (result != GSEC_OK) {
      return result;
    }
    for (i = 0; i < sizeof abc_msg; i++) {
      result = gsec_sha256_update(&ctx, abc_msg + i, 1);
      if (result != GSEC_OK) {
        gsec_wipe(&ctx, sizeof ctx);
        return result;
      }
    }
    result = gsec_sha256_final(&ctx, dig);
    if (result != GSEC_OK) {
      gsec_wipe(&ctx, sizeof ctx);
      return result;
    }
    result = gsec_equal(dig, abc_dig, sizeof dig);
    gsec_wipe(dig, sizeof dig);
    if (result != GSEC_OK) {
      return result == GSEC_ERR_MISMATCH ? GSEC_ERR_INTERNAL : result;
    }
  }
  return GSEC_OK;
}
