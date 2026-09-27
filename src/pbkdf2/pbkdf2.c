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
 * PBKDF2 is HMAC iterated a public number of times, and the blocks are
 * xored together. The iteration count, the block index, and the lengths
 * are public. The password bytes and the derived key are not a branch
 * condition.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/pbkdf2.h>
#include <ghoti.io/security/secret.h>

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
  if (hash == GSEC_PBKDF2_SHA512) {
    return GSEC_SHA512_DIGEST_LEN;
  }
  return 0;
}

static void copy_bytes(unsigned char * dst, const unsigned char * src, size_t n) {
  size_t i;

  for (i = 0; i < n; i++) {
    dst[i] = src[i];
  }
}

static void xor_bytes(unsigned char * dst, const unsigned char * src, size_t n) {
  size_t i;

  for (i = 0; i < n; i++) {
    dst[i] = (unsigned char)(dst[i] ^ src[i]);
  }
}

static void store_be32(unsigned char out[4], uint32_t value) {
  out[0] = (unsigned char)(value >> 24);
  out[1] = (unsigned char)(value >> 16);
  out[2] = (unsigned char)(value >> 8);
  out[3] = (unsigned char)value;
}

GSEC_Result gsec_pbkdf2(uint32_t hash, const void * password, size_t password_len,
    const void * salt, size_t salt_len, uint32_t iterations, unsigned char * dk,
    size_t dk_len) {
  unsigned char u[GSEC_SHA512_DIGEST_LEN];
  unsigned char t[GSEC_SHA512_DIGEST_LEN];
  unsigned char be[4];
  GSEC_Hmac ctx;
  size_t dig;
  size_t blocks;
  size_t filled;
  uint32_t block;
  GSEC_Result result;

  dig = digest_len(hash);
  if (dig == 0 || iterations == 0 || (password == NULL && password_len > 0) ||
      (salt == NULL && salt_len > 0) || (dk == NULL && dk_len > 0)) {
    return GSEC_ERR_INVALID;
  }
  if (dk_len == 0) {
    return GSEC_OK;
  }
  blocks = dk_len / dig;
  if (dk_len % dig != 0) {
    blocks++;
  }
  if (blocks > (size_t)UINT32_MAX) {
    return GSEC_ERR_LIMIT;
  }

  filled = 0;
  for (block = 1; block <= (uint32_t)blocks; block++) {
    uint32_t round;
    size_t take;

    store_be32(be, block);
    result = gsec_hmac_init(&ctx, hash, password, password_len);
    if (result == GSEC_OK && salt_len > 0) {
      result = gsec_hmac_update(&ctx, salt, salt_len);
    }
    if (result == GSEC_OK) {
      result = gsec_hmac_update(&ctx, be, sizeof be);
    }
    if (result == GSEC_OK) {
      result = gsec_hmac_final(&ctx, u);
    }
    if (result != GSEC_OK) {
      gsec_wipe(&ctx, sizeof ctx);
      gsec_wipe(u, sizeof u);
      gsec_wipe(t, sizeof t);
      gsec_wipe(be, sizeof be);
      gsec_wipe(dk, dk_len);
      return result;
    }
    copy_bytes(t, u, dig);
    for (round = 1; round < iterations; round++) {
      result = gsec_hmac(hash, password, password_len, u, dig, u);
      if (result != GSEC_OK) {
        gsec_wipe(u, sizeof u);
        gsec_wipe(t, sizeof t);
        gsec_wipe(be, sizeof be);
        gsec_wipe(dk, dk_len);
        return result;
      }
      xor_bytes(t, u, dig);
    }
    take = dk_len - filled;
    if (take > dig) {
      take = dig;
    }
    copy_bytes(dk + filled, t, take);
    filled += take;
  }
  gsec_wipe(u, sizeof u);
  gsec_wipe(t, sizeof t);
  gsec_wipe(be, sizeof be);
  return GSEC_OK;
}
