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
 * SHA-512 compression is additions, rotations, and bitwise functions from
 * FIPS 180-4 section 6.4. SHA-384 is that compression with the initial
 * value from section 5.3.4 and a 48-byte digest. The round constants are
 * indexed by the round number. The message schedule is arithmetic on the
 * block. Neither indexes memory with a message byte.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/sha384.h>
#include <ghoti.io/security/sha512.h>

#define GSEC_SHA512_MAGIC 0x53484135u
#define GSEC_SHA384_MAGIC 0x53483338u

_Static_assert(GSEC_SHA384_BLOCK_LEN == GSEC_SHA512_BLOCK_LEN,
    "SHA-384 and SHA-512 share one block size");

static const uint64_t K[80] = {
  0x428a2f98d728ae22u, 0x7137449123ef65cdu,
  0xb5c0fbcfec4d3b2fu, 0xe9b5dba58189dbbcu,
  0x3956c25bf348b538u, 0x59f111f1b605d019u,
  0x923f82a4af194f9bu, 0xab1c5ed5da6d8118u,
  0xd807aa98a3030242u, 0x12835b0145706fbeu,
  0x243185be4ee4b28cu, 0x550c7dc3d5ffb4e2u,
  0x72be5d74f27b896fu, 0x80deb1fe3b1696b1u,
  0x9bdc06a725c71235u, 0xc19bf174cf692694u,
  0xe49b69c19ef14ad2u, 0xefbe4786384f25e3u,
  0x0fc19dc68b8cd5b5u, 0x240ca1cc77ac9c65u,
  0x2de92c6f592b0275u, 0x4a7484aa6ea6e483u,
  0x5cb0a9dcbd41fbd4u, 0x76f988da831153b5u,
  0x983e5152ee66dfabu, 0xa831c66d2db43210u,
  0xb00327c898fb213fu, 0xbf597fc7beef0ee4u,
  0xc6e00bf33da88fc2u, 0xd5a79147930aa725u,
  0x06ca6351e003826fu, 0x142929670a0e6e70u,
  0x27b70a8546d22ffcu, 0x2e1b21385c26c926u,
  0x4d2c6dfc5ac42aedu, 0x53380d139d95b3dfu,
  0x650a73548baf63deu, 0x766a0abb3c77b2a8u,
  0x81c2c92e47edaee6u, 0x92722c851482353bu,
  0xa2bfe8a14cf10364u, 0xa81a664bbc423001u,
  0xc24b8b70d0f89791u, 0xc76c51a30654be30u,
  0xd192e819d6ef5218u, 0xd69906245565a910u,
  0xf40e35855771202au, 0x106aa07032bbd1b8u,
  0x19a4c116b8d2d0c8u, 0x1e376c085141ab53u,
  0x2748774cdf8eeb99u, 0x34b0bcb5e19b48a8u,
  0x391c0cb3c5c95a63u, 0x4ed8aa4ae3418acbu,
  0x5b9cca4f7763e373u, 0x682e6ff3d6b2b8a3u,
  0x748f82ee5defb2fcu, 0x78a5636f43172f60u,
  0x84c87814a1f0ab72u, 0x8cc702081a6439ecu,
  0x90befffa23631e28u, 0xa4506cebde82bde9u,
  0xbef9a3f7b2c67915u, 0xc67178f2e372532bu,
  0xca273eceea26619cu, 0xd186b8c721c0c207u,
  0xeada7dd6cde0eb1eu, 0xf57d4f7fee6ed178u,
  0x06f067aa72176fbau, 0x0a637dc5a2c898a6u,
  0x113f9804bef90daeu, 0x1b710b35131c471bu,
  0x28db77f523047d84u, 0x32caab7b40c72493u,
  0x3c9ebe0a15c9bebcu, 0x431d67c49c100d4cu,
  0x4cc5d4becb3e42b6u, 0x597f299cfc657e2au,
  0x5fcb6fab3ad6faecu, 0x6c44198c4a475817u
};

static uint64_t rotr(uint64_t x, unsigned n) {
  return (x >> n) | (x << (64u - n));
}

static uint64_t Ch(uint64_t x, uint64_t y, uint64_t z) {
  return (x & y) ^ (~x & z);
}

static uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

static uint64_t Sigma0(uint64_t x) {
  return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
}

static uint64_t Sigma1(uint64_t x) {
  return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
}

static uint64_t sigma0(uint64_t x) {
  return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7);
}

static uint64_t sigma1(uint64_t x) {
  return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6);
}

static uint64_t load_be(const unsigned char * p) {
  return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
      ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
      ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
      ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

static void store_be(unsigned char * p, uint64_t x) {
  p[0] = (unsigned char)(x >> 56);
  p[1] = (unsigned char)(x >> 48);
  p[2] = (unsigned char)(x >> 40);
  p[3] = (unsigned char)(x >> 32);
  p[4] = (unsigned char)(x >> 24);
  p[5] = (unsigned char)(x >> 16);
  p[6] = (unsigned char)(x >> 8);
  p[7] = (unsigned char)x;
}

static void compress(uint64_t state[8], const unsigned char block[128]) {
  uint64_t w[80];
  uint64_t s[8];
  unsigned i;

  for (i = 0; i < 16u; i++) {
    w[i] = load_be(block + (i * 8u));
  }
  for (i = 16u; i < 80u; i++) {
    w[i] = sigma1(w[i - 2u]) + w[i - 7u] + sigma0(w[i - 15u]) + w[i - 16u];
  }

  for (i = 0; i < 8u; i++) {
    s[i] = state[i];
  }

  for (i = 0; i < 80u; i++) {
    uint64_t t1 = s[7] + Sigma1(s[4]) + Ch(s[4], s[5], s[6]) + K[i] + w[i];
    uint64_t t2 = Sigma0(s[0]) + Maj(s[0], s[1], s[2]);
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
    state[i] += s[i];
  }

  /* The schedule and the working variables are the block. The chaining
   * value in the context is what the next block needs; these are not. */
  gsec_wipe(w, sizeof w);
  gsec_wipe(s, sizeof s);
}

static void absorb_block(uint64_t state[8], unsigned char block[128],
    size_t * block_len) {
  compress(state, block);
  gsec_wipe(block, GSEC_SHA512_BLOCK_LEN);
  *block_len = 0;
}

/* n bytes is n*8 bits. A size_t of bytes always fits in 128 bits. The
 * counter overflows only when earlier updates have already filled it. */
static int bits_fit(uint64_t hi, uint64_t lo, size_t n, uint64_t * new_hi,
    uint64_t * new_lo) {
  uint64_t add_hi = (uint64_t)n >> 61;
  uint64_t add_lo = (uint64_t)n << 3;
  uint64_t sum = lo + add_lo;
  uint64_t carry = sum < lo ? 1u : 0u;

  if (hi > UINT64_MAX - add_hi) {
    return 0;
  }
  if (hi + add_hi > UINT64_MAX - carry) {
    return 0;
  }
  *new_lo = sum;
  *new_hi = hi + add_hi + carry;
  return 1;
}

static GSEC_Result wide_update(uint64_t state[8], uint64_t * nbits_hi,
    uint64_t * nbits_lo, unsigned char * block, size_t * block_len,
    const void * data, size_t n) {
  const unsigned char * p;
  uint64_t new_hi;
  uint64_t new_lo;

  if (n == 0) {
    return GSEC_OK;
  }
  if (data == NULL) {
    return GSEC_ERR_INVALID;
  }
  if (!bits_fit(*nbits_hi, *nbits_lo, n, &new_hi, &new_lo)) {
    return GSEC_ERR_LIMIT;
  }
  *nbits_hi = new_hi;
  *nbits_lo = new_lo;

  p = (const unsigned char *)data;
  while (n > 0) {
    size_t room = GSEC_SHA512_BLOCK_LEN - *block_len;
    size_t take = n < room ? n : room;
    size_t i;

    for (i = 0; i < take; i++) {
      block[*block_len + i] = p[i];
    }
    *block_len += take;
    p += take;
    n -= take;
    if (*block_len == GSEC_SHA512_BLOCK_LEN) {
      absorb_block(state, block, block_len);
    }
  }
  return GSEC_OK;
}

static void wide_final(uint64_t state[8], uint64_t nbits_hi, uint64_t nbits_lo,
    unsigned char * block, size_t * block_len, unsigned char * out,
    unsigned digest_bytes) {
  unsigned i;

  block[(*block_len)++] = 0x80u;
  if (*block_len > 112u) {
    while (*block_len < GSEC_SHA512_BLOCK_LEN) {
      block[(*block_len)++] = 0;
    }
    absorb_block(state, block, block_len);
  }
  while (*block_len < 112u) {
    block[(*block_len)++] = 0;
  }
  store_be(block + 112, nbits_hi);
  store_be(block + 120, nbits_lo);
  compress(state, block);

  for (i = 0; i < digest_bytes / 8u; i++) {
    store_be(out + (i * 8u), state[i]);
  }
}

GSEC_Result gsec_sha512_init(GSEC_Sha512 * ctx) {
  if (ctx == NULL) {
    return GSEC_ERR_INVALID;
  }
  gsec_wipe(ctx, sizeof *ctx);
  ctx->state[0] = 0x6a09e667f3bcc908u;
  ctx->state[1] = 0xbb67ae8584caa73bu;
  ctx->state[2] = 0x3c6ef372fe94f82bu;
  ctx->state[3] = 0xa54ff53a5f1d36f1u;
  ctx->state[4] = 0x510e527fade682d1u;
  ctx->state[5] = 0x9b05688c2b3e6c1fu;
  ctx->state[6] = 0x1f83d9abfb41bd6bu;
  ctx->state[7] = 0x5be0cd19137e2179u;
  ctx->magic = GSEC_SHA512_MAGIC;
  return GSEC_OK;
}

GSEC_Result gsec_sha384_init(GSEC_Sha384 * ctx) {
  if (ctx == NULL) {
    return GSEC_ERR_INVALID;
  }
  gsec_wipe(ctx, sizeof *ctx);
  ctx->state[0] = 0xcbbb9d5dc1059ed8u;
  ctx->state[1] = 0x629a292a367cd507u;
  ctx->state[2] = 0x9159015a3070dd17u;
  ctx->state[3] = 0x152fecd8f70e5939u;
  ctx->state[4] = 0x67332667ffc00b31u;
  ctx->state[5] = 0x8eb44a8768581511u;
  ctx->state[6] = 0xdb0c2e0d64f98fa7u;
  ctx->state[7] = 0x47b5481dbefa4fa4u;
  ctx->magic = GSEC_SHA384_MAGIC;
  return GSEC_OK;
}

GSEC_Result gsec_sha512_update(GSEC_Sha512 * ctx, const void * data, size_t n) {
  GSEC_Result result;

  if (ctx == NULL || ctx->magic != GSEC_SHA512_MAGIC) {
    return GSEC_ERR_INVALID;
  }
  result = wide_update(ctx->state, &ctx->nbits_hi, &ctx->nbits_lo, ctx->block,
      &ctx->block_len, data, n);
  if (result == GSEC_ERR_LIMIT) {
    gsec_wipe(ctx, sizeof *ctx);
  }
  return result;
}

GSEC_Result gsec_sha384_update(GSEC_Sha384 * ctx, const void * data, size_t n) {
  GSEC_Result result;

  if (ctx == NULL || ctx->magic != GSEC_SHA384_MAGIC) {
    return GSEC_ERR_INVALID;
  }
  result = wide_update(ctx->state, &ctx->nbits_hi, &ctx->nbits_lo, ctx->block,
      &ctx->block_len, data, n);
  if (result == GSEC_ERR_LIMIT) {
    gsec_wipe(ctx, sizeof *ctx);
  }
  return result;
}

GSEC_Result gsec_sha512_final(GSEC_Sha512 * ctx, unsigned char * out) {
  if (ctx == NULL || ctx->magic != GSEC_SHA512_MAGIC) {
    return GSEC_ERR_INVALID;
  }
  if (out == NULL) {
    return GSEC_ERR_INVALID;
  }
  wide_final(ctx->state, ctx->nbits_hi, ctx->nbits_lo, ctx->block,
      &ctx->block_len, out, GSEC_SHA512_DIGEST_LEN);
  gsec_wipe(ctx, sizeof *ctx);
  return GSEC_OK;
}

GSEC_Result gsec_sha384_final(GSEC_Sha384 * ctx, unsigned char * out) {
  if (ctx == NULL || ctx->magic != GSEC_SHA384_MAGIC) {
    return GSEC_ERR_INVALID;
  }
  if (out == NULL) {
    return GSEC_ERR_INVALID;
  }
  wide_final(ctx->state, ctx->nbits_hi, ctx->nbits_lo, ctx->block,
      &ctx->block_len, out, GSEC_SHA384_DIGEST_LEN);
  gsec_wipe(ctx, sizeof *ctx);
  return GSEC_OK;
}

GSEC_Result gsec_sha512(const void * data, size_t n, unsigned char * out) {
  GSEC_Sha512 ctx;
  GSEC_Result result;

  result = gsec_sha512_init(&ctx);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_sha512_update(&ctx, data, n);
  if (result != GSEC_OK) {
    gsec_wipe(&ctx, sizeof ctx);
    return result;
  }
  result = gsec_sha512_final(&ctx, out);
  if (result != GSEC_OK) {
    gsec_wipe(&ctx, sizeof ctx);
  }
  return result;
}

GSEC_Result gsec_sha384(const void * data, size_t n, unsigned char * out) {
  GSEC_Sha384 ctx;
  GSEC_Result result;

  result = gsec_sha384_init(&ctx);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_sha384_update(&ctx, data, n);
  if (result != GSEC_OK) {
    gsec_wipe(&ctx, sizeof ctx);
    return result;
  }
  result = gsec_sha384_final(&ctx, out);
  if (result != GSEC_OK) {
    gsec_wipe(&ctx, sizeof ctx);
  }
  return result;
}
