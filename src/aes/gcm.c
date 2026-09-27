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
 * AES-GCM. The hash subkey is the encryption of the zero block. GHASH
 * multiplies in GF(2^128) by the schoolbook algorithm in SP 800-38D,
 * with a mask in place of the bit test. The counter for plaintext is
 * inc32 of J0, which is not the CTR primitive in ctr.c: that one
 * increments all 16 bytes, and GCM must not.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/aes_gcm.h>
#include <ghoti.io/security/secret.h>

#include <stdint.h>

static int key_len_ok(size_t n) {
  return n == GSEC_AES128_KEY_LEN || n == GSEC_AES192_KEY_LEN ||
      n == GSEC_AES256_KEY_LEN;
}

static int tag_len_ok(size_t n) {
  return n == 4u || n == 8u || (n >= 12u && n <= 16u);
}

static int bit_len_ok(size_t n) {
  return (uint64_t)n <= (UINT64_MAX >> 3);
}

static int pt_len_ok(size_t n) {
  return (uint64_t)n <= ((UINT64_C(1) << 36) - 32u);
}

static void store_be64(unsigned char out[8], uint64_t n) {
  unsigned i;

  for (i = 0; i < 8u; i++) {
    out[7u - i] = (unsigned char)n;
    n >>= 8;
  }
}

static void xor_block(unsigned char z[16], const unsigned char v[16]) {
  unsigned i;

  for (i = 0; i < 16u; i++) {
    z[i] = (unsigned char)(z[i] ^ v[i]);
  }
}

static void right_shift(unsigned char v[16]) {
  unsigned carry = 0;
  unsigned i;

  for (i = 0; i < 16u; i++) {
    unsigned next = v[i] & 1u;

    v[i] = (unsigned char)((v[i] >> 1) | (carry << 7));
    carry = next;
  }
}

static void ghash_mul(unsigned char x[16], const unsigned char h[16]) {
  unsigned char z[16];
  unsigned char v[16];
  unsigned i;
  unsigned j;

  for (i = 0; i < 16u; i++) {
    z[i] = 0;
    v[i] = x[i];
  }
  for (i = 0; i < 128u; i++) {
    unsigned bit = (h[i >> 3] >> (7u - (i & 7u))) & 1u;
    unsigned char mask = (unsigned char)(0u - bit);
    unsigned lsb;
    unsigned char lmask;

    for (j = 0; j < 16u; j++) {
      z[j] = (unsigned char)(z[j] ^ (v[j] & mask));
    }
    lsb = v[15] & 1u;
    lmask = (unsigned char)(0u - lsb);
    right_shift(v);
    v[0] = (unsigned char)(v[0] ^ (0xe1u & lmask));
  }
  for (i = 0; i < 16u; i++) {
    x[i] = z[i];
  }
  gsec_wipe(z, sizeof z);
  gsec_wipe(v, sizeof v);
}

static void ghash_absorb(unsigned char y[16], const unsigned char h[16],
    const unsigned char * data, size_t n) {
  size_t off = 0;

  while (off < n) {
    unsigned char block[16];
    size_t take = n - off;
    unsigned i;

    if (take > 16u) {
      take = 16u;
    }
    for (i = 0; i < 16u; i++) {
      block[i] = 0;
    }
    for (i = 0; i < take; i++) {
      block[i] = data[off + i];
    }
    xor_block(y, block);
    ghash_mul(y, h);
    gsec_wipe(block, sizeof block);
    off += take;
  }
}

static void ghash_lengths(unsigned char y[16], const unsigned char h[16],
    size_t aad_len, size_t data_len) {
  unsigned char block[16];

  store_be64(block, (uint64_t)aad_len << 3);
  store_be64(block + 8, (uint64_t)data_len << 3);
  xor_block(y, block);
  ghash_mul(y, h);
  gsec_wipe(block, sizeof block);
}

static void inc32(unsigned char block[16]) {
  unsigned carry = 1u;
  unsigned i;

  for (i = 0; i < 4u; i++) {
    unsigned index = 15u - i;
    unsigned sum = (unsigned)block[index] + carry;

    block[index] = (unsigned char)sum;
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

static int ranges_overlap(const unsigned char * a, size_t an,
    const unsigned char * b, size_t bn) {
  if (an == 0 || bn == 0) {
    return 0;
  }
  if (a <= b) {
    return (size_t)(b - a) < an;
  }
  return (size_t)(a - b) < bn;
}

static GSEC_Result make_j0(unsigned char j0[16], const unsigned char h[16],
    const unsigned char * iv, size_t iv_len) {
  unsigned i;

  if (iv_len == 12u) {
    for (i = 0; i < 12u; i++) {
      j0[i] = iv[i];
    }
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;
    return GSEC_OK;
  }
  for (i = 0; i < 16u; i++) {
    j0[i] = 0;
  }
  ghash_absorb(j0, h, iv, iv_len);
  ghash_lengths(j0, h, 0, iv_len);
  return GSEC_OK;
}

static GSEC_Result args_common(const void * key, size_t key_len,
    const void * iv, size_t iv_len, const void * aad, size_t aad_len,
    size_t data_len, const void * tag, size_t tag_len) {
  if (key == NULL || !key_len_ok(key_len) || iv == NULL || iv_len == 0 ||
      !bit_len_ok(iv_len) || (aad == NULL && aad_len != 0) ||
      !bit_len_ok(aad_len) || !pt_len_ok(data_len) || tag == NULL ||
      !tag_len_ok(tag_len)) {
    return !bit_len_ok(iv_len) || !bit_len_ok(aad_len) || !pt_len_ok(data_len)
        ? GSEC_ERR_LIMIT : GSEC_ERR_INVALID;
  }
  return GSEC_OK;
}

static void finish_tag(unsigned char tag[16], const unsigned char y[16],
    const unsigned char s[16]) {
  unsigned i;

  for (i = 0; i < 16u; i++) {
    tag[i] = (unsigned char)(y[i] ^ s[i]);
  }
}

GSEC_Result gsec_aes_gcm_encrypt(const void * key, size_t key_len,
    const void * iv, size_t iv_len, const void * aad, size_t aad_len,
    const void * pt, size_t pt_len, void * ct, void * tag, size_t tag_len) {
  GSEC_Aes aes;
  unsigned char h[16];
  unsigned char j0[16];
  unsigned char y[16];
  unsigned char s[16];
  unsigned char counter[16];
  unsigned char full[16];
  const unsigned char * src;
  unsigned char * dst;
  unsigned char * tag_out;
  GSEC_Result result;
  size_t off;
  unsigned i;

  result = args_common(key, key_len, iv, iv_len, aad, aad_len, pt_len, tag,
      tag_len);
  if (result != GSEC_OK) {
    return result;
  }
  if ((pt == NULL || ct == NULL) && pt_len != 0) {
    return GSEC_ERR_INVALID;
  }
  src = (const unsigned char *)pt;
  dst = (unsigned char *)ct;
  tag_out = (unsigned char *)tag;
  if (partial_overlap(src, dst, pt_len) ||
      ranges_overlap(tag_out, tag_len, src, pt_len) ||
      ranges_overlap(tag_out, tag_len, dst, pt_len)) {
    return GSEC_ERR_INVALID;
  }
  gsec_wipe(&aes, sizeof aes);
  result = gsec_aes_encrypt_init(&aes, key, key_len);
  if (result != GSEC_OK) {
    gsec_wipe(&aes, sizeof aes);
    return result;
  }
  for (i = 0; i < 16u; i++) {
    h[i] = 0;
    y[i] = 0;
  }
  result = gsec_aes_encrypt_block(&aes, h, h);
  if (result != GSEC_OK) {
    goto fail;
  }
  make_j0(j0, h, (const unsigned char *)iv, iv_len);
  if (aad_len != 0) {
    ghash_absorb(y, h, (const unsigned char *)aad, aad_len);
  }
  for (i = 0; i < 16u; i++) {
    counter[i] = j0[i];
  }
  for (off = 0; off < pt_len; ) {
    unsigned char block[16];
    unsigned char ks[16];
    size_t take = pt_len - off;

    if (take > 16u) {
      take = 16u;
    }
    inc32(counter);
    result = gsec_aes_encrypt_block(&aes, counter, ks);
    if (result != GSEC_OK) {
      gsec_wipe(ks, sizeof ks);
      if (off != 0) {
        gsec_wipe(dst, off);
      }
      goto fail;
    }
    for (i = 0; i < 16u; i++) {
      block[i] = 0;
    }
    for (i = 0; i < take; i++) {
      dst[off + i] = (unsigned char)(src[off + i] ^ ks[i]);
      block[i] = dst[off + i];
    }
    xor_block(y, block);
    ghash_mul(y, h);
    gsec_wipe(block, sizeof block);
    gsec_wipe(ks, sizeof ks);
    off += take;
  }
  ghash_lengths(y, h, aad_len, pt_len);
  result = gsec_aes_encrypt_block(&aes, j0, s);
  if (result != GSEC_OK) {
    if (pt_len != 0) {
      gsec_wipe(dst, pt_len);
    }
    goto fail;
  }
  finish_tag(full, y, s);
  for (i = 0; i < tag_len; i++) {
    tag_out[i] = full[i];
  }
  result = GSEC_OK;
fail:
  gsec_aes_encrypt_wipe(&aes);
  gsec_wipe(h, sizeof h);
  gsec_wipe(j0, sizeof j0);
  gsec_wipe(y, sizeof y);
  gsec_wipe(s, sizeof s);
  gsec_wipe(counter, sizeof counter);
  gsec_wipe(full, sizeof full);
  return result;
}

GSEC_Result gsec_aes_gcm_decrypt(const void * key, size_t key_len,
    const void * iv, size_t iv_len, const void * aad, size_t aad_len,
    const void * ct, size_t ct_len, void * pt, const void * tag,
    size_t tag_len) {
  GSEC_Aes aes;
  unsigned char h[16];
  unsigned char j0[16];
  unsigned char y[16];
  unsigned char s[16];
  unsigned char counter[16];
  unsigned char full[16];
  unsigned char given[16];
  const unsigned char * src;
  unsigned char * dst;
  GSEC_Result result;
  size_t off;
  unsigned i;

  result = args_common(key, key_len, iv, iv_len, aad, aad_len, ct_len, tag,
      tag_len);
  if (result != GSEC_OK) {
    return result;
  }
  if ((ct == NULL || pt == NULL) && ct_len != 0) {
    return GSEC_ERR_INVALID;
  }
  src = (const unsigned char *)ct;
  dst = (unsigned char *)pt;
  if (partial_overlap(src, dst, ct_len)) {
    return GSEC_ERR_INVALID;
  }
  for (i = 0; i < 16u; i++) {
    given[i] = 0;
  }
  for (i = 0; i < tag_len; i++) {
    given[i] = ((const unsigned char *)tag)[i];
  }
  gsec_wipe(&aes, sizeof aes);
  result = gsec_aes_encrypt_init(&aes, key, key_len);
  if (result != GSEC_OK) {
    gsec_wipe(given, sizeof given);
    gsec_wipe(&aes, sizeof aes);
    return result;
  }
  for (i = 0; i < 16u; i++) {
    h[i] = 0;
    y[i] = 0;
  }
  result = gsec_aes_encrypt_block(&aes, h, h);
  if (result != GSEC_OK) {
    goto fail;
  }
  make_j0(j0, h, (const unsigned char *)iv, iv_len);
  if (aad_len != 0) {
    ghash_absorb(y, h, (const unsigned char *)aad, aad_len);
  }
  for (i = 0; i < 16u; i++) {
    counter[i] = j0[i];
  }
  for (off = 0; off < ct_len; ) {
    unsigned char block[16];
    unsigned char ks[16];
    size_t take = ct_len - off;

    if (take > 16u) {
      take = 16u;
    }
    for (i = 0; i < 16u; i++) {
      block[i] = 0;
    }
    for (i = 0; i < take; i++) {
      block[i] = src[off + i];
    }
    xor_block(y, block);
    ghash_mul(y, h);
    inc32(counter);
    result = gsec_aes_encrypt_block(&aes, counter, ks);
    if (result != GSEC_OK) {
      gsec_wipe(block, sizeof block);
      gsec_wipe(ks, sizeof ks);
      if (off != 0) {
        gsec_wipe(dst, off);
      }
      goto fail;
    }
    for (i = 0; i < take; i++) {
      dst[off + i] = (unsigned char)(block[i] ^ ks[i]);
    }
    gsec_wipe(block, sizeof block);
    gsec_wipe(ks, sizeof ks);
    off += take;
  }
  ghash_lengths(y, h, aad_len, ct_len);
  result = gsec_aes_encrypt_block(&aes, j0, s);
  if (result != GSEC_OK) {
    if (ct_len != 0) {
      gsec_wipe(dst, ct_len);
    }
    goto fail;
  }
  finish_tag(full, y, s);
  result = gsec_equal(given, full, tag_len);
  if (result != GSEC_OK && ct_len != 0) {
    gsec_wipe(dst, ct_len);
  }
fail:
  gsec_aes_encrypt_wipe(&aes);
  gsec_wipe(h, sizeof h);
  gsec_wipe(j0, sizeof j0);
  gsec_wipe(y, sizeof y);
  gsec_wipe(s, sizeof s);
  gsec_wipe(counter, sizeof counter);
  gsec_wipe(full, sizeof full);
  gsec_wipe(given, sizeof given);
  return result;
}
