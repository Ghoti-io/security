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
 * SHA-1 compression is FIPS 180-4 section 6.1. The round constants and the
 * bitwise function are selected by the round number. The message schedule
 * is rotations and exclusive-or of the block. Neither indexes memory with
 * a message byte.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/sha1.h>

#define GSEC_SHA1_MAGIC 0x53484131u

static uint32_t rotl(uint32_t x, unsigned n) {
  return (x << n) | (x >> (32u - n));
}

static uint32_t f(unsigned t, uint32_t b, uint32_t c, uint32_t d) {
  if (t < 20u) {
    return (b & c) ^ (~b & d);
  }
  if (t < 40u) {
    return b ^ c ^ d;
  }
  if (t < 60u) {
    return (b & c) ^ (b & d) ^ (c & d);
  }
  return b ^ c ^ d;
}

static uint32_t K(unsigned t) {
  if (t < 20u) {
    return 0x5a827999u;
  }
  if (t < 40u) {
    return 0x6ed9eba1u;
  }
  if (t < 60u) {
    return 0x8f1bbcdcu;
  }
  return 0xca62c1d6u;
}

static uint32_t load_be(const unsigned char * p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
      ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be(unsigned char * p, uint32_t x) {
  p[0] = (unsigned char)(x >> 24);
  p[1] = (unsigned char)(x >> 16);
  p[2] = (unsigned char)(x >> 8);
  p[3] = (unsigned char)x;
}

static int live(const GSEC_Sha1 * ctx) {
  return ctx->magic == GSEC_SHA1_MAGIC;
}

static void compress(GSEC_Sha1 * ctx, const unsigned char block[64]) {
  uint32_t w[80];
  uint32_t s[5];
  unsigned i;

  for (i = 0; i < 16u; i++) {
    w[i] = load_be(block + (i * 4u));
  }
  for (i = 16u; i < 80u; i++) {
    w[i] = rotl(w[i - 3u] ^ w[i - 8u] ^ w[i - 14u] ^ w[i - 16u], 1);
  }

  for (i = 0; i < 5u; i++) {
    s[i] = ctx->state[i];
  }

  for (i = 0; i < 80u; i++) {
    uint32_t t = rotl(s[0], 5) + f(i, s[1], s[2], s[3]) + s[4] + K(i) + w[i];
    s[4] = s[3];
    s[3] = s[2];
    s[2] = rotl(s[1], 30);
    s[1] = s[0];
    s[0] = t;
  }

  for (i = 0; i < 5u; i++) {
    ctx->state[i] += s[i];
  }

  /* The schedule and the working variables are the block. The chaining
   * value in the context is what the next block needs; these are not. */
  gsec_wipe(w, sizeof w);
  gsec_wipe(s, sizeof s);
}

static void absorb_block(GSEC_Sha1 * ctx) {
  compress(ctx, ctx->block);
  gsec_wipe(ctx->block, sizeof ctx->block);
  ctx->block_len = 0;
}

GSEC_Result gsec_sha1_init(GSEC_Sha1 * ctx) {
  if (ctx == NULL) {
    return GSEC_ERR_INVALID;
  }
  gsec_wipe(ctx, sizeof *ctx);
  ctx->state[0] = 0x67452301u;
  ctx->state[1] = 0xefcdab89u;
  ctx->state[2] = 0x98badcfeu;
  ctx->state[3] = 0x10325476u;
  ctx->state[4] = 0xc3d2e1f0u;
  ctx->magic = GSEC_SHA1_MAGIC;
  return GSEC_OK;
}

GSEC_Result gsec_sha1_update(GSEC_Sha1 * ctx, const void * data, size_t n) {
  const unsigned char * p;
  uint64_t add;

  if (ctx == NULL || !live(ctx)) {
    return GSEC_ERR_INVALID;
  }
  if (n == 0) {
    return GSEC_OK;
  }
  if (data == NULL) {
    return GSEC_ERR_INVALID;
  }
  /* n bits must fit in the 64-bit counter FIPS 180-4 section 5.1 uses.
   * Check before any byte is absorbed, and kill the context if it does
   * not: a caller who keeps hashing after a refusal would otherwise
   * finish a prefix. */
  if (n > (UINT64_MAX >> 3)) {
    gsec_wipe(ctx, sizeof *ctx);
    return GSEC_ERR_LIMIT;
  }
  add = (uint64_t)n << 3;
  if (ctx->nbits > UINT64_MAX - add) {
    gsec_wipe(ctx, sizeof *ctx);
    return GSEC_ERR_LIMIT;
  }
  ctx->nbits += add;

  p = (const unsigned char *)data;
  while (n > 0) {
    size_t room = GSEC_SHA1_BLOCK_LEN - ctx->block_len;
    size_t take = n < room ? n : room;
    size_t i;

    for (i = 0; i < take; i++) {
      ctx->block[ctx->block_len + i] = p[i];
    }
    ctx->block_len += take;
    p += take;
    n -= take;
    if (ctx->block_len == GSEC_SHA1_BLOCK_LEN) {
      absorb_block(ctx);
    }
  }
  return GSEC_OK;
}

GSEC_Result gsec_sha1_final(GSEC_Sha1 * ctx, unsigned char * out) {
  unsigned i;

  if (ctx == NULL || !live(ctx)) {
    return GSEC_ERR_INVALID;
  }
  if (out == NULL) {
    return GSEC_ERR_INVALID;
  }

  ctx->block[ctx->block_len++] = 0x80u;
  if (ctx->block_len > 56u) {
    while (ctx->block_len < GSEC_SHA1_BLOCK_LEN) {
      ctx->block[ctx->block_len++] = 0;
    }
    absorb_block(ctx);
  }
  while (ctx->block_len < 56u) {
    ctx->block[ctx->block_len++] = 0;
  }
  store_be(ctx->block + 56, (uint32_t)(ctx->nbits >> 32));
  store_be(ctx->block + 60, (uint32_t)ctx->nbits);
  compress(ctx, ctx->block);

  for (i = 0; i < 5u; i++) {
    store_be(out + (i * 4u), ctx->state[i]);
  }
  gsec_wipe(ctx, sizeof *ctx);
  return GSEC_OK;
}

GSEC_Result gsec_sha1(const void * data, size_t n, unsigned char * out) {
  GSEC_Sha1 ctx;
  GSEC_Result result;

  result = gsec_sha1_init(&ctx);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_sha1_update(&ctx, data, n);
  if (result != GSEC_OK) {
    gsec_wipe(&ctx, sizeof ctx);
    return result;
  }
  result = gsec_sha1_final(&ctx, out);
  if (result != GSEC_OK) {
    gsec_wipe(&ctx, sizeof ctx);
  }
  return result;
}
