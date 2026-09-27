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
 * scrypt. The Salsa20/8 core, BlockMix, and ROMix are RFC 7914. N, r,
 * and p are public. The password is not a branch condition and not a
 * table index.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/allocator.h>
#include <ghoti.io/security/pbkdf2.h>
#include <ghoti.io/security/scrypt.h>
#include <ghoti.io/security/secret.h>

#include <stdint.h>
#include <string.h>

static uint32_t rotl(uint32_t x, int n) {
  return (x << n) | (x >> (32 - n));
}

static void salsa20_8(uint32_t b[16]) {
  uint32_t x[16];
  int i;

  for (i = 0; i < 16; i++) {
    x[i] = b[i];
  }
  for (i = 0; i < 4; i++) {
    x[4] ^= rotl(x[0] + x[12], 7);
    x[8] ^= rotl(x[4] + x[0], 9);
    x[12] ^= rotl(x[8] + x[4], 13);
    x[0] ^= rotl(x[12] + x[8], 18);
    x[9] ^= rotl(x[5] + x[1], 7);
    x[13] ^= rotl(x[9] + x[5], 9);
    x[1] ^= rotl(x[13] + x[9], 13);
    x[5] ^= rotl(x[1] + x[13], 18);
    x[14] ^= rotl(x[10] + x[6], 7);
    x[2] ^= rotl(x[14] + x[10], 9);
    x[6] ^= rotl(x[2] + x[14], 13);
    x[10] ^= rotl(x[6] + x[2], 18);
    x[3] ^= rotl(x[15] + x[11], 7);
    x[7] ^= rotl(x[3] + x[15], 9);
    x[11] ^= rotl(x[7] + x[3], 13);
    x[15] ^= rotl(x[11] + x[7], 18);
    x[1] ^= rotl(x[0] + x[3], 7);
    x[2] ^= rotl(x[1] + x[0], 9);
    x[3] ^= rotl(x[2] + x[1], 13);
    x[0] ^= rotl(x[3] + x[2], 18);
    x[6] ^= rotl(x[5] + x[4], 7);
    x[7] ^= rotl(x[6] + x[5], 9);
    x[4] ^= rotl(x[7] + x[6], 13);
    x[5] ^= rotl(x[4] + x[7], 18);
    x[11] ^= rotl(x[10] + x[9], 7);
    x[8] ^= rotl(x[11] + x[10], 9);
    x[9] ^= rotl(x[8] + x[11], 13);
    x[10] ^= rotl(x[9] + x[8], 18);
    x[12] ^= rotl(x[15] + x[14], 7);
    x[13] ^= rotl(x[12] + x[15], 9);
    x[14] ^= rotl(x[13] + x[12], 13);
    x[15] ^= rotl(x[14] + x[13], 18);
  }
  for (i = 0; i < 16; i++) {
    b[i] += x[i];
  }
  gsec_wipe(x, sizeof x);
}

static void block_xor(unsigned char * dst, const unsigned char * src, size_t n) {
  size_t i;

  for (i = 0; i < n; i++) {
    dst[i] = (unsigned char)(dst[i] ^ src[i]);
  }
}

static void blockmix(unsigned char * b, unsigned char * y, uint32_t r) {
  unsigned char x[64];
  uint32_t i;
  size_t block = 64;

  memcpy(x, b + (2u * r - 1u) * block, block);
  for (i = 0; i < 2u * r; i++) {
    uint32_t words[16];
    int w;

    block_xor(x, b + i * block, block);
    for (w = 0; w < 16; w++) {
      words[w] = (uint32_t)x[w * 4] | ((uint32_t)x[w * 4 + 1] << 8) |
          ((uint32_t)x[w * 4 + 2] << 16) | ((uint32_t)x[w * 4 + 3] << 24);
    }
    salsa20_8(words);
    for (w = 0; w < 16; w++) {
      x[w * 4] = (unsigned char)words[w];
      x[w * 4 + 1] = (unsigned char)(words[w] >> 8);
      x[w * 4 + 2] = (unsigned char)(words[w] >> 16);
      x[w * 4 + 3] = (unsigned char)(words[w] >> 24);
    }
    memcpy(y + i * block, x, block);
    gsec_wipe(words, sizeof words);
  }
  for (i = 0; i < r; i++) {
    memcpy(b + i * block, y + (2u * i) * block, block);
    memcpy(b + (r + i) * block, y + (2u * i + 1u) * block, block);
  }
  gsec_wipe(x, sizeof x);
}

static void romix(unsigned char * b, unsigned char * v, unsigned char * xy,
    uint64_t n, uint32_t r) {
  size_t blen = (size_t)128u * r;
  uint64_t i;

  memcpy(xy, b, blen);
  for (i = 0; i < n; i++) {
    memcpy(v + i * blen, xy, blen);
    blockmix(xy, xy + blen, r);
  }
  for (i = 0; i < n; i++) {
    uint64_t j;
    const unsigned char * last = xy + blen - 64;

    j = (uint64_t)last[0] | ((uint64_t)last[1] << 8) |
        ((uint64_t)last[2] << 16) | ((uint64_t)last[3] << 24) |
        ((uint64_t)last[4] << 32) | ((uint64_t)last[5] << 40) |
        ((uint64_t)last[6] << 48) | ((uint64_t)last[7] << 56);
    j &= n - 1u;
    block_xor(xy, v + j * blen, blen);
    blockmix(xy, xy + blen, r);
  }
  memcpy(b, xy, blen);
}

static int power_of_two(uint64_t n) {
  return n >= 2u && (n & (n - 1u)) == 0u;
}

GSEC_Result gsec_scrypt(const void * password, size_t password_len,
    const void * salt, size_t salt_len, uint64_t n, uint32_t r, uint32_t p,
    void * dk, size_t dk_len) {
  const GSEC_Allocator * alloc;
  unsigned char * b;
  unsigned char * v;
  unsigned char * xy;
  size_t blen;
  size_t bytes;
  uint32_t i;
  GSEC_Result result;

  if ((password == NULL && password_len != 0) ||
      (salt == NULL && salt_len != 0) || (dk == NULL && dk_len != 0) ||
      !power_of_two(n) || r == 0 || p == 0) {
    return GSEC_ERR_INVALID;
  }
  if (r > (UINT32_MAX / 128u) || p > (SIZE_MAX / ((size_t)128u * r))) {
    return GSEC_ERR_LIMIT;
  }
  blen = (size_t)128u * r;
  if (n > SIZE_MAX / blen) {
    return GSEC_ERR_LIMIT;
  }
  bytes = blen * (size_t)n;
  if (bytes / blen != (size_t)n || bytes > GSEC_SCRYPT_MEMORY_MAX) {
    return GSEC_ERR_LIMIT;
  }
  if (p > (GSEC_SCRYPT_MEMORY_MAX - bytes) / blen) {
    return GSEC_ERR_LIMIT;
  }
  if (blen * 2u > GSEC_SCRYPT_MEMORY_MAX - bytes - p * blen) {
    return GSEC_ERR_LIMIT;
  }
  alloc = gsec_allocator_default();
  b = (unsigned char *)alloc->calloc_fn(alloc->ctx, p, blen);
  v = (unsigned char *)alloc->calloc_fn(alloc->ctx, (size_t)n, blen);
  xy = (unsigned char *)alloc->calloc_fn(alloc->ctx, 2u, blen);
  if (b == NULL || v == NULL || xy == NULL) {
    alloc->free_fn(alloc->ctx, b);
    alloc->free_fn(alloc->ctx, v);
    alloc->free_fn(alloc->ctx, xy);
    return GSEC_ERR_LIMIT;
  }
  result = gsec_pbkdf2(GSEC_PBKDF2_SHA256, password, password_len, salt,
      salt_len, 1, b, blen * p);
  if (result != GSEC_OK) {
    goto done;
  }
  for (i = 0; i < p; i++) {
    romix(b + i * blen, v, xy, n, r);
  }
  result = gsec_pbkdf2(GSEC_PBKDF2_SHA256, password, password_len, b,
      blen * p, 1, (unsigned char *)dk, dk_len);
done:
  gsec_wipe(b, blen * p);
  gsec_wipe(v, blen * (size_t)n);
  gsec_wipe(xy, blen * 2u);
  alloc->free_fn(alloc->ctx, b);
  alloc->free_fn(alloc->ctx, v);
  alloc->free_fn(alloc->ctx, xy);
  return result;
}
