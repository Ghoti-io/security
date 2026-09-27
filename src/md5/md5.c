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
 * MD5 compression is RFC 1321. Words are little-endian. The round function,
 * the shift, the constant, and which block word is added are selected by
 * the round number. None of them indexes memory with a message byte.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/md5.h>
#include <ghoti.io/security/secret.h>

#define GSEC_MD5_MAGIC 0x4d443501u

/* T[i] = floor(2^32 * abs(sin(i + 1))), i from 0. RFC 1321 section 3.4. */
static const uint32_t T[64] = {
  0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
  0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
  0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
  0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
  0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
  0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
  0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
  0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
  0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
  0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
  0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
  0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
  0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
  0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
  0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
  0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
};

static const unsigned char SHIFT[64] = {
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static uint32_t rotl(uint32_t x, unsigned n) {
  return (x << n) | (x >> (32u - n));
}

static uint32_t word_index(unsigned round) {
  if (round < 16u) {
    return round;
  }
  if (round < 32u) {
    return (5u * round + 1u) & 15u;
  }
  if (round < 48u) {
    return (3u * round + 5u) & 15u;
  }
  return (7u * round) & 15u;
}

static uint32_t aux(unsigned round, uint32_t b, uint32_t c, uint32_t d) {
  if (round < 16u) {
    return (b & c) | (~b & d);
  }
  if (round < 32u) {
    return (b & d) | (c & ~d);
  }
  if (round < 48u) {
    return b ^ c ^ d;
  }
  return c ^ (b | ~d);
}

static uint32_t load_le(const unsigned char * p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
      ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store_le(unsigned char * p, uint32_t x) {
  p[0] = (unsigned char)x;
  p[1] = (unsigned char)(x >> 8);
  p[2] = (unsigned char)(x >> 16);
  p[3] = (unsigned char)(x >> 24);
}

static int live(const GSEC_Md5 * ctx) {
  return ctx->magic == GSEC_MD5_MAGIC;
}

static void compress(GSEC_Md5 * ctx, const unsigned char block[64]) {
  uint32_t x[16];
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
  unsigned i;

  for (i = 0; i < 16u; i++) {
    x[i] = load_le(block + (i * 4u));
  }
  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];

  for (i = 0; i < 64u; i++) {
    uint32_t next_a = d;
    uint32_t next_c = b;
    uint32_t next_d = c;
    uint32_t sum = a + aux(i, b, c, d) + x[word_index(i)] + T[i];

    b = b + rotl(sum, SHIFT[i]);
    a = next_a;
    c = next_c;
    d = next_d;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;

  /* The block words and the working variables are this block. The chaining
   * value in the context is what the next block needs; these are not. */
  gsec_wipe(x, sizeof x);
  gsec_wipe(&a, sizeof a);
  gsec_wipe(&b, sizeof b);
  gsec_wipe(&c, sizeof c);
  gsec_wipe(&d, sizeof d);
}

static void absorb_block(GSEC_Md5 * ctx) {
  compress(ctx, ctx->block);
  gsec_wipe(ctx->block, sizeof ctx->block);
  ctx->block_len = 0;
}

GSEC_Result gsec_md5_init(GSEC_Md5 * ctx) {
  if (ctx == NULL) {
    return GSEC_ERR_INVALID;
  }
  gsec_wipe(ctx, sizeof *ctx);
  ctx->state[0] = 0x67452301u;
  ctx->state[1] = 0xefcdab89u;
  ctx->state[2] = 0x98badcfeu;
  ctx->state[3] = 0x10325476u;
  ctx->magic = GSEC_MD5_MAGIC;
  return GSEC_OK;
}

GSEC_Result gsec_md5_update(GSEC_Md5 * ctx, const void * data, size_t n) {
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
  /* n bits must fit in the 64-bit counter RFC 1321 section 3.1 uses.
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
    size_t room = GSEC_MD5_BLOCK_LEN - ctx->block_len;
    size_t take = n < room ? n : room;
    size_t i;

    for (i = 0; i < take; i++) {
      ctx->block[ctx->block_len + i] = p[i];
    }
    ctx->block_len += take;
    p += take;
    n -= take;
    if (ctx->block_len == GSEC_MD5_BLOCK_LEN) {
      absorb_block(ctx);
    }
  }
  return GSEC_OK;
}

GSEC_Result gsec_md5_final(GSEC_Md5 * ctx, unsigned char * out) {
  unsigned i;

  if (ctx == NULL || !live(ctx)) {
    return GSEC_ERR_INVALID;
  }
  if (out == NULL) {
    return GSEC_ERR_INVALID;
  }

  ctx->block[ctx->block_len++] = 0x80u;
  if (ctx->block_len > 56u) {
    while (ctx->block_len < GSEC_MD5_BLOCK_LEN) {
      ctx->block[ctx->block_len++] = 0;
    }
    absorb_block(ctx);
  }
  while (ctx->block_len < 56u) {
    ctx->block[ctx->block_len++] = 0;
  }
  store_le(ctx->block + 56, (uint32_t)ctx->nbits);
  store_le(ctx->block + 60, (uint32_t)(ctx->nbits >> 32));
  compress(ctx, ctx->block);

  for (i = 0; i < 4u; i++) {
    store_le(out + (i * 4u), ctx->state[i]);
  }
  gsec_wipe(ctx, sizeof *ctx);
  return GSEC_OK;
}

GSEC_Result gsec_md5(const void * data, size_t n, unsigned char * out) {
  GSEC_Md5 ctx;
  GSEC_Result result;

  result = gsec_md5_init(&ctx);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_md5_update(&ctx, data, n);
  if (result != GSEC_OK) {
    gsec_wipe(&ctx, sizeof ctx);
    return result;
  }
  result = gsec_md5_final(&ctx, out);
  if (result != GSEC_OK) {
    gsec_wipe(&ctx, sizeof ctx);
  }
  return result;
}
