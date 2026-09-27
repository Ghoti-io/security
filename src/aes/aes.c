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
 * AES as FIPS 197. The S-box is the inverse in GF(2^8) followed by the
 * affine map, and the inverse is computed by exponentiation, so a data
 * byte never selects a table entry. The round index is public.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/aes.h>
#include <ghoti.io/security/secret.h>

#define GSEC_AES_MAGIC 0x41455331u

static const unsigned char RCON[11] = {
  0x00u,
  0x01u, 0x02u, 0x04u, 0x08u, 0x10u, 0x20u, 0x40u, 0x80u, 0x1bu, 0x36u
};

static unsigned char xtime(unsigned char x) {
  unsigned hi = (unsigned)(x >> 7);
  return (unsigned char)((x << 1) ^ (0x1bu & (unsigned char)(0u - hi)));
}

static unsigned char gf_mul(unsigned char a, unsigned char b) {
  unsigned char product = 0;
  unsigned i;

  for (i = 0; i < 8u; i++) {
    unsigned mask = 0u - (unsigned)(b & 1u);
    product = (unsigned char)(product ^ (a & (unsigned char)mask));
    a = xtime(a);
    b = (unsigned char)(b >> 1);
  }
  return product;
}

static unsigned char rotr8(unsigned char x, unsigned n) {
  return (unsigned char)((x >> n) | (x << (8u - n)));
}

static unsigned char affine(unsigned char b) {
  return (unsigned char)(b ^ rotr8(b, 4) ^ rotr8(b, 5) ^ rotr8(b, 6) ^
      rotr8(b, 7) ^ 0x63u);
}

static unsigned char inv_affine(unsigned char b) {
  return (unsigned char)(rotr8(b, 2) ^ rotr8(b, 5) ^ rotr8(b, 7) ^ 0x05u);
}

static unsigned char gf_inv(unsigned char a) {
  unsigned char a2 = gf_mul(a, a);
  unsigned char a4 = gf_mul(a2, a2);
  unsigned char a8 = gf_mul(a4, a4);
  unsigned char a16 = gf_mul(a8, a8);
  unsigned char a32 = gf_mul(a16, a16);
  unsigned char a64 = gf_mul(a32, a32);
  unsigned char a128 = gf_mul(a64, a64);

  return gf_mul(a128,
      gf_mul(a64, gf_mul(a32, gf_mul(a16, gf_mul(a8, gf_mul(a4, a2))))));
}

static unsigned char sbox(unsigned char x) {
  return affine(gf_inv(x));
}

static unsigned char inv_sbox(unsigned char x) {
  return gf_inv(inv_affine(x));
}

static int live(const GSEC_Aes * ctx) {
  return ctx->magic == GSEC_AES_MAGIC &&
      (ctx->nrounds == 10u || ctx->nrounds == 12u || ctx->nrounds == 14u);
}

static void sub_bytes(unsigned char s[16]) {
  unsigned i;

  for (i = 0; i < 16u; i++) {
    s[i] = sbox(s[i]);
  }
}

static void inv_sub_bytes(unsigned char s[16]) {
  unsigned i;

  for (i = 0; i < 16u; i++) {
    s[i] = inv_sbox(s[i]);
  }
}

static void shift_rows(unsigned char s[16]) {
  unsigned char t;

  t = s[1];
  s[1] = s[5];
  s[5] = s[9];
  s[9] = s[13];
  s[13] = t;

  t = s[2];
  s[2] = s[10];
  s[10] = t;
  t = s[6];
  s[6] = s[14];
  s[14] = t;

  t = s[15];
  s[15] = s[11];
  s[11] = s[7];
  s[7] = s[3];
  s[3] = t;
}

static void inv_shift_rows(unsigned char s[16]) {
  unsigned char t;

  t = s[13];
  s[13] = s[9];
  s[9] = s[5];
  s[5] = s[1];
  s[1] = t;

  t = s[2];
  s[2] = s[10];
  s[10] = t;
  t = s[6];
  s[6] = s[14];
  s[14] = t;

  t = s[3];
  s[3] = s[7];
  s[7] = s[11];
  s[11] = s[15];
  s[15] = t;
}

static void mix_column(unsigned char c[4]) {
  unsigned char a = c[0];
  unsigned char b = c[1];
  unsigned char d = c[2];
  unsigned char e = c[3];
  unsigned char t = (unsigned char)(a ^ b ^ d ^ e);

  c[0] = (unsigned char)(a ^ t ^ xtime((unsigned char)(a ^ b)));
  c[1] = (unsigned char)(b ^ t ^ xtime((unsigned char)(b ^ d)));
  c[2] = (unsigned char)(d ^ t ^ xtime((unsigned char)(d ^ e)));
  c[3] = (unsigned char)(e ^ t ^ xtime((unsigned char)(e ^ a)));
}

static void mix_columns(unsigned char s[16]) {
  unsigned c;

  for (c = 0; c < 4u; c++) {
    mix_column(s + (c * 4u));
  }
}

static void inv_mix_column(unsigned char c[4]) {
  unsigned char a = c[0];
  unsigned char b = c[1];
  unsigned char d = c[2];
  unsigned char e = c[3];

  c[0] = (unsigned char)(gf_mul(a, 0x0eu) ^ gf_mul(b, 0x0bu) ^
      gf_mul(d, 0x0du) ^ gf_mul(e, 0x09u));
  c[1] = (unsigned char)(gf_mul(a, 0x09u) ^ gf_mul(b, 0x0eu) ^
      gf_mul(d, 0x0bu) ^ gf_mul(e, 0x0du));
  c[2] = (unsigned char)(gf_mul(a, 0x0du) ^ gf_mul(b, 0x09u) ^
      gf_mul(d, 0x0eu) ^ gf_mul(e, 0x0bu));
  c[3] = (unsigned char)(gf_mul(a, 0x0bu) ^ gf_mul(b, 0x0du) ^
      gf_mul(d, 0x09u) ^ gf_mul(e, 0x0eu));
}

static void inv_mix_columns(unsigned char s[16]) {
  unsigned c;

  for (c = 0; c < 4u; c++) {
    inv_mix_column(s + (c * 4u));
  }
}

static void add_round_key(unsigned char s[16], const unsigned char * rk) {
  unsigned i;

  for (i = 0; i < 16u; i++) {
    s[i] = (unsigned char)(s[i] ^ rk[i]);
  }
}

static void copy_bytes(unsigned char * dst, const unsigned char * src, size_t n) {
  size_t i;

  for (i = 0; i < n; i++) {
    dst[i] = src[i];
  }
}

static void expand(GSEC_Aes * ctx, const unsigned char * key, unsigned nk,
    unsigned nrounds) {
  unsigned char temp[4];
  unsigned total = 4u * (nrounds + 1u);
  unsigned i;
  unsigned b;

  copy_bytes(ctx->round_key, key, (size_t)nk * 4u);
  i = nk;
  while (i < total) {
    temp[0] = ctx->round_key[(i - 1u) * 4u];
    temp[1] = ctx->round_key[(i - 1u) * 4u + 1u];
    temp[2] = ctx->round_key[(i - 1u) * 4u + 2u];
    temp[3] = ctx->round_key[(i - 1u) * 4u + 3u];
    if (i % nk == 0u) {
      unsigned char rot = temp[0];
      temp[0] = sbox(temp[1]);
      temp[1] = sbox(temp[2]);
      temp[2] = sbox(temp[3]);
      temp[3] = sbox(rot);
      temp[0] = (unsigned char)(temp[0] ^ RCON[i / nk]);
    } else if (nk > 6u && i % nk == 4u) {
      temp[0] = sbox(temp[0]);
      temp[1] = sbox(temp[1]);
      temp[2] = sbox(temp[2]);
      temp[3] = sbox(temp[3]);
    }
    for (b = 0; b < 4u; b++) {
      ctx->round_key[i * 4u + b] = (unsigned char)(
          ctx->round_key[(i - nk) * 4u + b] ^ temp[b]);
    }
    i++;
  }
  gsec_wipe(temp, sizeof temp);
  ctx->nrounds = nrounds;
  ctx->magic = GSEC_AES_MAGIC;
}

static int key_shape(size_t key_len, unsigned * nk, unsigned * nrounds) {
  if (key_len == GSEC_AES128_KEY_LEN) {
    *nk = 4u;
    *nrounds = 10u;
    return 1;
  }
  if (key_len == GSEC_AES192_KEY_LEN) {
    *nk = 6u;
    *nrounds = 12u;
    return 1;
  }
  if (key_len == GSEC_AES256_KEY_LEN) {
    *nk = 8u;
    *nrounds = 14u;
    return 1;
  }
  return 0;
}

static void encrypt_state(const GSEC_Aes * ctx, unsigned char s[16]) {
  unsigned round;

  add_round_key(s, ctx->round_key);
  for (round = 1; round < ctx->nrounds; round++) {
    sub_bytes(s);
    shift_rows(s);
    mix_columns(s);
    add_round_key(s, ctx->round_key + (round * 16u));
  }
  sub_bytes(s);
  shift_rows(s);
  add_round_key(s, ctx->round_key + (ctx->nrounds * 16u));
}

static void decrypt_state(const GSEC_Aes * ctx, unsigned char s[16]) {
  unsigned round;

  add_round_key(s, ctx->round_key + (ctx->nrounds * 16u));
  round = ctx->nrounds;
  while (round > 1u) {
    round--;
    inv_shift_rows(s);
    inv_sub_bytes(s);
    add_round_key(s, ctx->round_key + (round * 16u));
    inv_mix_columns(s);
  }
  inv_shift_rows(s);
  inv_sub_bytes(s);
  add_round_key(s, ctx->round_key);
}

GSEC_Result gsec_aes_encrypt_init(GSEC_Aes * ctx, const void * key,
    size_t key_len) {
  unsigned nk;
  unsigned nrounds;

  if (ctx == NULL) {
    return GSEC_ERR_INVALID;
  }
  gsec_wipe(ctx, sizeof *ctx);
  if (key == NULL || !key_shape(key_len, &nk, &nrounds)) {
    return GSEC_ERR_INVALID;
  }
  expand(ctx, (const unsigned char *)key, nk, nrounds);
  return GSEC_OK;
}

GSEC_Result gsec_aes_encrypt_block(const GSEC_Aes * ctx, const void * in,
    void * out) {
  unsigned char s[16];

  if (ctx == NULL || !live(ctx) || in == NULL || out == NULL) {
    return GSEC_ERR_INVALID;
  }
  copy_bytes(s, (const unsigned char *)in, 16u);
  encrypt_state(ctx, s);
  copy_bytes((unsigned char *)out, s, 16u);
  gsec_wipe(s, sizeof s);
  return GSEC_OK;
}

GSEC_Result gsec_aes_decrypt_block(const GSEC_Aes * ctx, const void * in,
    void * out) {
  unsigned char s[16];

  if (ctx == NULL || !live(ctx) || in == NULL || out == NULL) {
    return GSEC_ERR_INVALID;
  }
  copy_bytes(s, (const unsigned char *)in, 16u);
  decrypt_state(ctx, s);
  copy_bytes((unsigned char *)out, s, 16u);
  gsec_wipe(s, sizeof s);
  return GSEC_OK;
}

GSEC_Result gsec_aes_encrypt(const void * key, size_t key_len, const void * in,
    void * out) {
  GSEC_Aes ctx;
  GSEC_Result result;

  result = gsec_aes_encrypt_init(&ctx, key, key_len);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_aes_encrypt_block(&ctx, in, out);
  gsec_wipe(&ctx, sizeof ctx);
  return result;
}

GSEC_Result gsec_aes_decrypt(const void * key, size_t key_len, const void * in,
    void * out) {
  GSEC_Aes ctx;
  GSEC_Result result;

  result = gsec_aes_encrypt_init(&ctx, key, key_len);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_aes_decrypt_block(&ctx, in, out);
  gsec_wipe(&ctx, sizeof ctx);
  return result;
}

GSEC_Result gsec_aes_encrypt_wipe(GSEC_Aes * ctx) {
  if (ctx == NULL) {
    return GSEC_ERR_INVALID;
  }
  gsec_wipe(ctx, sizeof *ctx);
  return GSEC_OK;
}
