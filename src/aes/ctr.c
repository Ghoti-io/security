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
 * AES-CTR. The counter block is incremented as an integer in the
 * direction the caller named. That direction is public. The keystream
 * is the encryption of the counter, and a plaintext byte is not a branch
 * condition.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/aes_ctr.h>
#include <ghoti.io/security/secret.h>

#define GSEC_AES_CTR_MAGIC 0x41435452u

static int live(const GSEC_Aes_Ctr * ctx) {
  return ctx->magic == GSEC_AES_CTR_MAGIC &&
      (ctx->direction == GSEC_AES_CTR_BE || ctx->direction == GSEC_AES_CTR_LE);
}

static void copy_bytes(unsigned char * dst, const unsigned char * src, size_t n) {
  size_t i;

  for (i = 0; i < n; i++) {
    dst[i] = src[i];
  }
}

static void increment(unsigned char counter[GSEC_AES_BLOCK_LEN], uint32_t direction) {
  unsigned carry = 1u;
  unsigned i;

  for (i = 0; i < GSEC_AES_BLOCK_LEN; i++) {
    unsigned index = direction == GSEC_AES_CTR_LE ? i : (GSEC_AES_BLOCK_LEN - 1u - i);
    unsigned sum = (unsigned)counter[index] + carry;

    counter[index] = (unsigned char)sum;
    carry = sum >> 8;
  }
}

static int partial_overlap(const unsigned char * a, const unsigned char * b,
    size_t n) {
  if (n == 0 || a == b) {
    return 0;
  }
  if (a < b) {
    return (size_t)(b - a) < n;
  }
  return (size_t)(a - b) < n;
}

static GSEC_Result refill(GSEC_Aes_Ctr * ctx) {
  GSEC_Result result;

  result = gsec_aes_encrypt_block(&ctx->aes, ctx->counter, ctx->stream);
  if (result != GSEC_OK) {
    gsec_wipe(ctx, sizeof *ctx);
    return result;
  }
  increment(ctx->counter, ctx->direction);
  ctx->offset = 0;
  return GSEC_OK;
}

GSEC_Result gsec_aes_ctr_init(GSEC_Aes_Ctr * ctx, const void * key,
    size_t key_len, const void * counter, uint32_t direction) {
  GSEC_Result result;

  if (ctx == NULL) {
    return GSEC_ERR_INVALID;
  }
  gsec_wipe(ctx, sizeof *ctx);
  if (counter == NULL ||
      (direction != GSEC_AES_CTR_BE && direction != GSEC_AES_CTR_LE)) {
    return GSEC_ERR_INVALID;
  }
  result = gsec_aes_encrypt_init(&ctx->aes, key, key_len);
  if (result != GSEC_OK) {
    gsec_wipe(ctx, sizeof *ctx);
    return result;
  }
  copy_bytes(ctx->counter, (const unsigned char *)counter, GSEC_AES_BLOCK_LEN);
  ctx->direction = direction;
  ctx->offset = GSEC_AES_BLOCK_LEN;
  ctx->magic = GSEC_AES_CTR_MAGIC;
  return GSEC_OK;
}

GSEC_Result gsec_aes_ctr_update(GSEC_Aes_Ctr * ctx, const void * in, void * out,
    size_t n) {
  const unsigned char * src;
  unsigned char * dst;

  if (ctx == NULL || !live(ctx)) {
    return GSEC_ERR_INVALID;
  }
  if (n == 0) {
    return GSEC_OK;
  }
  if (in == NULL || out == NULL) {
    return GSEC_ERR_INVALID;
  }
  src = (const unsigned char *)in;
  dst = (unsigned char *)out;
  if (partial_overlap(src, dst, n)) {
    return GSEC_ERR_INVALID;
  }
  while (n > 0) {
    size_t room;
    size_t take;
    size_t i;
    GSEC_Result result;

    if (ctx->offset == GSEC_AES_BLOCK_LEN) {
      result = refill(ctx);
      if (result != GSEC_OK) {
        return result;
      }
    }
    room = GSEC_AES_BLOCK_LEN - ctx->offset;
    take = n < room ? n : room;
    for (i = 0; i < take; i++) {
      dst[i] = (unsigned char)(src[i] ^ ctx->stream[ctx->offset + i]);
    }
    ctx->offset += take;
    src += take;
    dst += take;
    n -= take;
  }
  return GSEC_OK;
}

GSEC_Result gsec_aes_ctr(const void * key, size_t key_len, const void * counter,
    uint32_t direction, const void * in, void * out, size_t n) {
  GSEC_Aes_Ctr ctx;
  GSEC_Result result;

  result = gsec_aes_ctr_init(&ctx, key, key_len, counter, direction);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_aes_ctr_update(&ctx, in, out, n);
  gsec_wipe(&ctx, sizeof ctx);
  return result;
}

GSEC_Result gsec_aes_ctr_wipe(GSEC_Aes_Ctr * ctx) {
  if (ctx == NULL) {
    return GSEC_ERR_INVALID;
  }
  gsec_wipe(ctx, sizeof *ctx);
  return GSEC_OK;
}
