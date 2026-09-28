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
 * RC2 as RFC 2268 specifies it. The substitution table is indexed by
 * key bytes, which is why this cipher is not in the constant-time gate.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/rc2.h>
#include <ghoti.io/security/secret.h>

#include <stdint.h>
#include <string.h>

static const unsigned char PITABLE[256] = {
  0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed,
  0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
  0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e,
  0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
  0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13,
  0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
  0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b,
  0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
  0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c,
  0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
  0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1,
  0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
  0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57,
  0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
  0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7,
  0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
  0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7,
  0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
  0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74,
  0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
  0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc,
  0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
  0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a,
  0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
  0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae,
  0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
  0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c,
  0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
  0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0,
  0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
  0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77,
  0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad
};

static uint16_t rotl(uint16_t x, unsigned n) {
  return (uint16_t)((x << n) | (x >> (16u - n)));
}

static uint16_t rotr(uint16_t x, unsigned n) {
  return (uint16_t)((x >> n) | (x << (16u - n)));
}

static int expand(uint16_t K[64], const unsigned char * key, size_t key_len,
    uint32_t effective_bits) {
  unsigned char L[128];
  unsigned t8;
  unsigned tm;
  unsigned i;
  int back;

  if (key_len < GSEC_RC2_KEY_MIN || key_len > GSEC_RC2_KEY_MAX ||
      effective_bits < GSEC_RC2_EFFECTIVE_MIN ||
      effective_bits > GSEC_RC2_EFFECTIVE_MAX) {
    return 0;
  }
  for (i = 0; i < key_len; i++) {
    L[i] = key[i];
  }
  for (i = (unsigned)key_len; i < 128u; i++) {
    L[i] = PITABLE[(L[i - 1u] + L[i - key_len]) & 0xffu];
  }
  t8 = (effective_bits + 7u) / 8u;
  tm = 255u % (1u << (8u + effective_bits - 8u * t8));
  L[128u - t8] = PITABLE[L[128u - t8] & tm];
  for (back = (int)(127u - t8); back >= 0; back--) {
    L[back] = PITABLE[L[back + 1] ^ L[(unsigned)back + t8]];
  }
  for (i = 0; i < 64u; i++) {
    K[i] = (uint16_t)(L[2u * i] + 256u * L[2u * i + 1u]);
  }
  gsec_wipe(L, sizeof L);
  return 1;
}

static void mix(uint16_t R[4], const uint16_t * K) {
  R[0] = (uint16_t)(R[0] + K[0] + (R[3] & R[2]) + ((~R[3]) & R[1]));
  R[0] = rotl(R[0], 1);
  R[1] = (uint16_t)(R[1] + K[1] + (R[0] & R[3]) + ((~R[0]) & R[2]));
  R[1] = rotl(R[1], 2);
  R[2] = (uint16_t)(R[2] + K[2] + (R[1] & R[0]) + ((~R[1]) & R[3]));
  R[2] = rotl(R[2], 3);
  R[3] = (uint16_t)(R[3] + K[3] + (R[2] & R[1]) + ((~R[2]) & R[0]));
  R[3] = rotl(R[3], 5);
}

static void rmix(uint16_t R[4], const uint16_t * K) {
  R[3] = rotr(R[3], 5);
  R[3] = (uint16_t)(R[3] - (K[3] + (R[2] & R[1]) + ((~R[2]) & R[0])));
  R[2] = rotr(R[2], 3);
  R[2] = (uint16_t)(R[2] - (K[2] + (R[1] & R[0]) + ((~R[1]) & R[3])));
  R[1] = rotr(R[1], 2);
  R[1] = (uint16_t)(R[1] - (K[1] + (R[0] & R[3]) + ((~R[0]) & R[2])));
  R[0] = rotr(R[0], 1);
  R[0] = (uint16_t)(R[0] - (K[0] + (R[3] & R[2]) + ((~R[3]) & R[1])));
}

static void mash(uint16_t R[4], const uint16_t * K) {
  R[0] = (uint16_t)(R[0] + K[R[3] & 63u]);
  R[1] = (uint16_t)(R[1] + K[R[0] & 63u]);
  R[2] = (uint16_t)(R[2] + K[R[1] & 63u]);
  R[3] = (uint16_t)(R[3] + K[R[2] & 63u]);
}

static void rmash(uint16_t R[4], const uint16_t * K) {
  R[3] = (uint16_t)(R[3] - K[R[2] & 63u]);
  R[2] = (uint16_t)(R[2] - K[R[1] & 63u]);
  R[1] = (uint16_t)(R[1] - K[R[0] & 63u]);
  R[0] = (uint16_t)(R[0] - K[R[3] & 63u]);
}

static void load_block(uint16_t R[4], const unsigned char * in) {
  unsigned i;

  for (i = 0; i < 4u; i++) {
    R[i] = (uint16_t)(in[2u * i] | ((uint16_t)in[2u * i + 1u] << 8));
  }
}

static void store_block(unsigned char * out, const uint16_t R[4]) {
  unsigned i;

  for (i = 0; i < 4u; i++) {
    out[2u * i] = (unsigned char)R[i];
    out[2u * i + 1u] = (unsigned char)(R[i] >> 8);
  }
}

static void encrypt_block(uint16_t R[4], const uint16_t * K) {
  unsigned i;
  unsigned j = 0;

  for (i = 0; i < 5u; i++, j += 4u) {
    mix(R, K + j);
  }
  mash(R, K);
  for (i = 0; i < 6u; i++, j += 4u) {
    mix(R, K + j);
  }
  mash(R, K);
  for (i = 0; i < 5u; i++, j += 4u) {
    mix(R, K + j);
  }
}

static void decrypt_block(uint16_t R[4], const uint16_t * K) {
  int j = 60;
  unsigned i;

  for (i = 0; i < 5u; i++, j -= 4) {
    rmix(R, K + j);
  }
  rmash(R, K);
  for (i = 0; i < 6u; i++, j -= 4) {
    rmix(R, K + j);
  }
  rmash(R, K);
  for (i = 0; i < 5u; i++, j -= 4) {
    rmix(R, K + j);
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

GSEC_Result gsec_rc2_encrypt(const void * key, size_t key_len,
    uint32_t effective_bits, const void * in, void * out) {
  uint16_t K[64];
  uint16_t R[4];

  if (key == NULL || in == NULL || out == NULL ||
      !expand(K, (const unsigned char *)key, key_len, effective_bits)) {
    return GSEC_ERR_INVALID;
  }
  load_block(R, (const unsigned char *)in);
  encrypt_block(R, K);
  store_block((unsigned char *)out, R);
  gsec_wipe(K, sizeof K);
  gsec_wipe(R, sizeof R);
  return GSEC_OK;
}

GSEC_Result gsec_rc2_decrypt(const void * key, size_t key_len,
    uint32_t effective_bits, const void * in, void * out) {
  uint16_t K[64];
  uint16_t R[4];

  if (key == NULL || in == NULL || out == NULL ||
      !expand(K, (const unsigned char *)key, key_len, effective_bits)) {
    return GSEC_ERR_INVALID;
  }
  load_block(R, (const unsigned char *)in);
  decrypt_block(R, K);
  store_block((unsigned char *)out, R);
  gsec_wipe(K, sizeof K);
  gsec_wipe(R, sizeof R);
  return GSEC_OK;
}

static GSEC_Result cbc(const void * key, size_t key_len, uint32_t effective_bits,
    const void * iv, const void * in, size_t len, void * out, int decrypt) {
  const unsigned char * src;
  unsigned char * dst;
  unsigned char prev[GSEC_RC2_BLOCK_LEN];
  unsigned char block[GSEC_RC2_BLOCK_LEN];
  size_t off;
  unsigned i;
  GSEC_Result result = GSEC_OK;

  if (iv == NULL || key == NULL) {
    return GSEC_ERR_INVALID;
  }
  if ((len % GSEC_RC2_BLOCK_LEN) != 0) {
    return GSEC_ERR_INVALID;
  }
  if (len == 0) {
    return GSEC_OK;
  }
  if (in == NULL || out == NULL) {
    return GSEC_ERR_INVALID;
  }
  src = (const unsigned char *)in;
  dst = (unsigned char *)out;
  if (partial_overlap(src, dst, len)) {
    return GSEC_ERR_INVALID;
  }
  memcpy(prev, iv, GSEC_RC2_BLOCK_LEN);
  for (off = 0; off < len; off += GSEC_RC2_BLOCK_LEN) {
    if (!decrypt) {
      for (i = 0; i < GSEC_RC2_BLOCK_LEN; i++) {
        block[i] = (unsigned char)(src[off + i] ^ prev[i]);
      }
      result = gsec_rc2_encrypt(key, key_len, effective_bits, block, dst + off);
      memcpy(prev, dst + off, GSEC_RC2_BLOCK_LEN);
    } else {
      memcpy(block, src + off, GSEC_RC2_BLOCK_LEN);
      result = gsec_rc2_decrypt(key, key_len, effective_bits, block, dst + off);
      for (i = 0; i < GSEC_RC2_BLOCK_LEN; i++) {
        dst[off + i] = (unsigned char)(dst[off + i] ^ prev[i]);
      }
      memcpy(prev, block, GSEC_RC2_BLOCK_LEN);
    }
    if (result != GSEC_OK) {
      gsec_wipe(prev, sizeof prev);
      gsec_wipe(block, sizeof block);
      return result;
    }
  }
  gsec_wipe(prev, sizeof prev);
  gsec_wipe(block, sizeof block);
  return GSEC_OK;
}

GSEC_Result gsec_rc2_cbc_encrypt(const void * key, size_t key_len,
    uint32_t effective_bits, const void * iv, const void * in, size_t len,
    void * out) {
  return cbc(key, key_len, effective_bits, iv, in, len, out, 0);
}

GSEC_Result gsec_rc2_cbc_decrypt(const void * key, size_t key_len,
    uint32_t effective_bits, const void * iv, const void * in, size_t len,
    void * out) {
  return cbc(key, key_len, effective_bits, iv, in, len, out, 1);
}
