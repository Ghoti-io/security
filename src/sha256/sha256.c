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
 * SHA-256 compression is additions, rotations, and bitwise functions from
 * FIPS 180-4 section 6.2. The round constants are indexed by the round
 * number. The message schedule is arithmetic on the block. Neither indexes
 * memory with a message byte.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/sha256.h>

#define GSEC_SHA256_MAGIC 0x53484132u

static const uint32_t K[64] = {
  0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
  0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
  0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
  0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
  0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
  0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
  0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
  0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
  0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
  0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
  0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static uint32_t rotr(uint32_t x, unsigned n) {
  return (x >> n) | (x << (32u - n));
}

static uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (~x & z);
}

static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

static uint32_t Sigma0(uint32_t x) {
  return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

static uint32_t Sigma1(uint32_t x) {
  return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

static uint32_t sigma0(uint32_t x) {
  return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

static uint32_t sigma1(uint32_t x) {
  return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
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

static int live(const GSEC_Sha256 * ctx) {
  return ctx->magic == GSEC_SHA256_MAGIC;
}

static void compress(GSEC_Sha256 * ctx, const unsigned char block[64]) {
  uint32_t w[64];
  uint32_t s[8];
  unsigned i;

  for (i = 0; i < 16u; i++) {
    w[i] = load_be(block + (i * 4u));
  }
  for (i = 16u; i < 64u; i++) {
    w[i] = sigma1(w[i - 2u]) + w[i - 7u] + sigma0(w[i - 15u]) + w[i - 16u];
  }

  for (i = 0; i < 8u; i++) {
    s[i] = ctx->state[i];
  }

  for (i = 0; i < 64u; i++) {
    uint32_t t1 = s[7] + Sigma1(s[4]) + Ch(s[4], s[5], s[6]) + K[i] + w[i];
    uint32_t t2 = Sigma0(s[0]) + Maj(s[0], s[1], s[2]);
    s[7] = s[6];
    s[6] = s[5];
    s[5] = s[4];
    s[4] = s[3] + t1;
    s[3] = s[2];
    s[2] = s[1];
    s[1] = s[0];
    s[0] = t1 + t2;
  }

  for (i = 0; i < 8u; i++) {
    ctx->state[i] += s[i];
  }

  /* The schedule and the working variables are the block. The chaining
   * value in the context is what the next block needs; these are not. */
  gsec_wipe(w, sizeof w);
  gsec_wipe(s, sizeof s);
}

static void absorb_block(GSEC_Sha256 * ctx) {
  compress(ctx, ctx->block);
  gsec_wipe(ctx->block, sizeof ctx->block);
  ctx->block_len = 0;
}

GSEC_Result gsec_sha256_init(GSEC_Sha256 * ctx) {
  if (ctx == NULL) {
    return GSEC_ERR_INVALID;
  }
  gsec_wipe(ctx, sizeof *ctx);
  ctx->state[0] = 0x6a09e667u;
  ctx->state[1] = 0xbb67ae85u;
  ctx->state[2] = 0x3c6ef372u;
  ctx->state[3] = 0xa54ff53au;
  ctx->state[4] = 0x510e527fu;
  ctx->state[5] = 0x9b05688cu;
  ctx->state[6] = 0x1f83d9abu;
  ctx->state[7] = 0x5be0cd19u;
  ctx->magic = GSEC_SHA256_MAGIC;
  return GSEC_OK;
}

GSEC_Result gsec_sha256_update(GSEC_Sha256 * ctx, const void * data, size_t n) {
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
    size_t room = GSEC_SHA256_BLOCK_LEN - ctx->block_len;
    size_t take = n < room ? n : room;
    size_t i;

    for (i = 0; i < take; i++) {
      ctx->block[ctx->block_len + i] = p[i];
    }
    ctx->block_len += take;
    p += take;
    n -= take;
    if (ctx->block_len == GSEC_SHA256_BLOCK_LEN) {
      absorb_block(ctx);
    }
  }
  return GSEC_OK;
}

GSEC_Result gsec_sha256_final(GSEC_Sha256 * ctx, unsigned char * out) {
  unsigned i;

  if (ctx == NULL || !live(ctx)) {
    return GSEC_ERR_INVALID;
  }
  if (out == NULL) {
    return GSEC_ERR_INVALID;
  }

  ctx->block[ctx->block_len++] = 0x80u;
  if (ctx->block_len > 56u) {
    while (ctx->block_len < GSEC_SHA256_BLOCK_LEN) {
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

  for (i = 0; i < 8u; i++) {
    store_be(out + (i * 4u), ctx->state[i]);
  }
  gsec_wipe(ctx, sizeof *ctx);
  return GSEC_OK;
}

GSEC_Result gsec_sha256(const void * data, size_t n, unsigned char * out) {
  GSEC_Sha256 ctx;
  GSEC_Result result;

  result = gsec_sha256_init(&ctx);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_sha256_update(&ctx, data, n);
  if (result != GSEC_OK) {
    gsec_wipe(&ctx, sizeof ctx);
    return result;
  }
  result = gsec_sha256_final(&ctx, out);
  if (result != GSEC_OK) {
    gsec_wipe(&ctx, sizeof ctx);
  }
  return result;
}
