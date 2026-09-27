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
 * AES-CBC. Each block is combined with the previous ciphertext block, or
 * with the initialization vector for the first block. The block count is
 * public. A plaintext byte is not a branch condition.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/aes_cbc.h>
#include <ghoti.io/security/secret.h>

static int key_ok(size_t key_len) {
  return key_len == GSEC_AES128_KEY_LEN || key_len == GSEC_AES192_KEY_LEN ||
      key_len == GSEC_AES256_KEY_LEN;
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

static void xor_block(unsigned char out[GSEC_AES_BLOCK_LEN],
    const unsigned char * a, const unsigned char * b) {
  unsigned i;

  for (i = 0; i < GSEC_AES_BLOCK_LEN; i++) {
    out[i] = (unsigned char)(a[i] ^ b[i]);
  }
}

static GSEC_Result check(const void * key, size_t key_len, const void * iv,
    const void * in, size_t len, void * out) {
  if (key == NULL || !key_ok(key_len) || iv == NULL) {
    return GSEC_ERR_INVALID;
  }
  if ((len % GSEC_AES_BLOCK_LEN) != 0) {
    return GSEC_ERR_INVALID;
  }
  if (len == 0) {
    return GSEC_OK;
  }
  if (in == NULL || out == NULL) {
    return GSEC_ERR_INVALID;
  }
  if (partial_overlap((const unsigned char *)in, (unsigned char *)out, len)) {
    return GSEC_ERR_INVALID;
  }
  return GSEC_OK;
}

GSEC_Result gsec_aes_cbc_encrypt(const void * key, size_t key_len,
    const void * iv, const void * in, size_t len, void * out) {
  GSEC_Aes ctx;
  const unsigned char * src;
  unsigned char * dst;
  unsigned char prev[GSEC_AES_BLOCK_LEN];
  unsigned char block[GSEC_AES_BLOCK_LEN];
  GSEC_Result result;
  size_t off;
  unsigned i;

  result = check(key, key_len, iv, in, len, out);
  if (result != GSEC_OK || len == 0) {
    return result;
  }
  result = gsec_aes_encrypt_init(&ctx, key, key_len);
  if (result != GSEC_OK) {
    return result;
  }
  src = (const unsigned char *)in;
  dst = (unsigned char *)out;
  for (off = 0; off < GSEC_AES_BLOCK_LEN; off++) {
    prev[off] = ((const unsigned char *)iv)[off];
  }
  for (off = 0; off < len; off += GSEC_AES_BLOCK_LEN) {
    xor_block(block, src + off, prev);
    result = gsec_aes_encrypt_block(&ctx, block, dst + off);
    if (result != GSEC_OK) {
      gsec_wipe(&ctx, sizeof ctx);
      gsec_wipe(prev, sizeof prev);
      gsec_wipe(block, sizeof block);
      gsec_wipe(dst, off);
      return result;
    }
    for (i = 0; i < GSEC_AES_BLOCK_LEN; i++) {
      prev[i] = dst[off + i];
    }
  }
  gsec_wipe(&ctx, sizeof ctx);
  gsec_wipe(prev, sizeof prev);
  gsec_wipe(block, sizeof block);
  return GSEC_OK;
}

GSEC_Result gsec_aes_cbc_decrypt(const void * key, size_t key_len,
    const void * iv, const void * in, size_t len, void * out) {
  GSEC_Aes ctx;
  const unsigned char * src;
  unsigned char * dst;
  unsigned char prev[GSEC_AES_BLOCK_LEN];
  unsigned char cipher[GSEC_AES_BLOCK_LEN];
  unsigned char plain[GSEC_AES_BLOCK_LEN];
  GSEC_Result result;
  size_t off;
  unsigned i;

  result = check(key, key_len, iv, in, len, out);
  if (result != GSEC_OK || len == 0) {
    return result;
  }
  result = gsec_aes_encrypt_init(&ctx, key, key_len);
  if (result != GSEC_OK) {
    return result;
  }
  src = (const unsigned char *)in;
  dst = (unsigned char *)out;
  for (i = 0; i < GSEC_AES_BLOCK_LEN; i++) {
    prev[i] = ((const unsigned char *)iv)[i];
  }
  for (off = 0; off < len; off += GSEC_AES_BLOCK_LEN) {
    for (i = 0; i < GSEC_AES_BLOCK_LEN; i++) {
      cipher[i] = src[off + i];
    }
    result = gsec_aes_decrypt_block(&ctx, cipher, plain);
    if (result != GSEC_OK) {
      gsec_wipe(&ctx, sizeof ctx);
      gsec_wipe(prev, sizeof prev);
      gsec_wipe(cipher, sizeof cipher);
      gsec_wipe(plain, sizeof plain);
      gsec_wipe(dst, off);
      return result;
    }
    xor_block(dst + off, plain, prev);
    for (i = 0; i < GSEC_AES_BLOCK_LEN; i++) {
      prev[i] = cipher[i];
    }
  }
  gsec_wipe(&ctx, sizeof ctx);
  gsec_wipe(prev, sizeof prev);
  gsec_wipe(cipher, sizeof cipher);
  gsec_wipe(plain, sizeof plain);
  return GSEC_OK;
}
