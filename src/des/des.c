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
 * DES and three-key Triple DES. The substitution boxes are public tables
 * indexed by bits of the round input. That index depends on the key, which
 * is why this cipher is not in the constant-time gate.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/des.h>
#include <ghoti.io/security/secret.h>

#include <stdint.h>

/* Bit positions are 1-based from the most significant bit, as FIPS 46-3
 * numbers them. */
static const uint8_t IP[64] = {
  58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};

static const uint8_t FP[64] = {
  40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
};

static const uint8_t E[48] = {
  32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
  12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
  22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
};

static const uint8_t P[32] = {
  16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
  2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
};

static const uint8_t PC1[56] = {
  57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
  10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
  14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
};

static const uint8_t PC2[48] = {
  14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
  23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

static const uint8_t SHIFTS[16] = {
  1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

/* Four rows of sixteen columns. The row is the outer two bits. */
static const uint8_t SBOX[8][64] = {
  {
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
  },
  {
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
  },
  {
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
  },
  {
    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
  },
  {
    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
  },
  {
    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
  },
  {
    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
  },
  {
    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
  }
};

static uint64_t load_be(const unsigned char in[8]) {
  uint64_t v = 0;
  int i;

  for (i = 0; i < 8; i++) {
    v = (v << 8) | in[i];
  }
  return v;
}

static void store_be(unsigned char out[8], uint64_t v) {
  int i;

  for (i = 7; i >= 0; i--) {
    out[i] = (unsigned char)v;
    v >>= 8;
  }
}

static int bit_at(uint64_t v, int pos, int width) {
  return (int)((v >> (width - pos)) & 1ull);
}

static uint64_t permute(uint64_t in, const uint8_t * table, int n, int width) {
  uint64_t out = 0;
  int i;

  for (i = 0; i < n; i++) {
    out = (out << 1) | (uint64_t)bit_at(in, table[i], width);
  }
  return out;
}

static uint32_t rotl28(uint32_t v, int n) {
  v &= 0x0fffffffu;
  return ((v << n) | (v >> (28 - n))) & 0x0fffffffu;
}

static void schedule(uint64_t subkeys[16], const unsigned char key[8],
    int reverse) {
  uint64_t pc1 = permute(load_be(key), PC1, 56, 64);
  uint32_t c = (uint32_t)(pc1 >> 28);
  uint32_t d = (uint32_t)(pc1 & 0x0fffffffu);
  int round;

  for (round = 0; round < 16; round++) {
    uint64_t cd;
    int slot = reverse ? 15 - round : round;

    c = rotl28(c, SHIFTS[round]);
    d = rotl28(d, SHIFTS[round]);
    cd = ((uint64_t)c << 28) | d;
    subkeys[slot] = permute(cd, PC2, 48, 56);
  }
}

static uint32_t feistel(uint32_t r, uint64_t subkey) {
  uint64_t expanded = permute(r, E, 48, 32) ^ subkey;
  uint32_t joined = 0;
  int box;

  for (box = 0; box < 8; box++) {
    int chunk = (int)((expanded >> (42 - 6 * box)) & 0x3fu);
    int row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
    int col = (chunk >> 1) & 0x0f;

    joined = (joined << 4) | SBOX[box][row * 16 + col];
  }
  return (uint32_t)permute(joined, P, 32, 32);
}

static uint64_t crypt_block(uint64_t block, const uint64_t subkeys[16]) {
  uint64_t ip = permute(block, IP, 64, 64);
  uint32_t l = (uint32_t)(ip >> 32);
  uint32_t r = (uint32_t)ip;
  int round;

  for (round = 0; round < 16; round++) {
    uint32_t next = l ^ feistel(r, subkeys[round]);

    l = r;
    r = next;
  }
  return permute(((uint64_t)r << 32) | l, FP, 64, 64);
}

static void one_block(const unsigned char key[8], const unsigned char in[8],
    unsigned char out[8], int reverse) {
  uint64_t subkeys[16];

  schedule(subkeys, key, reverse);
  store_be(out, crypt_block(load_be(in), subkeys));
  gsec_wipe(subkeys, sizeof subkeys);
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

GSEC_Result gsec_des_encrypt(const void * key, const void * in, void * out) {
  if (key == NULL || in == NULL || out == NULL) {
    return GSEC_ERR_INVALID;
  }
  one_block((const unsigned char *)key, (const unsigned char *)in,
      (unsigned char *)out, 0);
  return GSEC_OK;
}

GSEC_Result gsec_des_decrypt(const void * key, const void * in, void * out) {
  if (key == NULL || in == NULL || out == NULL) {
    return GSEC_ERR_INVALID;
  }
  one_block((const unsigned char *)key, (const unsigned char *)in,
      (unsigned char *)out, 1);
  return GSEC_OK;
}

GSEC_Result gsec_des_ede3_encrypt(const void * key, const void * in,
    void * out) {
  unsigned char block[GSEC_DES_BLOCK_LEN];
  const unsigned char * k;

  if (key == NULL || in == NULL || out == NULL) {
    return GSEC_ERR_INVALID;
  }
  k = (const unsigned char *)key;
  one_block(k, (const unsigned char *)in, block, 0);
  one_block(k + GSEC_DES_KEY_LEN, block, block, 1);
  one_block(k + 2u * GSEC_DES_KEY_LEN, block, (unsigned char *)out, 0);
  gsec_wipe(block, sizeof block);
  return GSEC_OK;
}

GSEC_Result gsec_des_ede3_decrypt(const void * key, const void * in,
    void * out) {
  unsigned char block[GSEC_DES_BLOCK_LEN];
  const unsigned char * k;

  if (key == NULL || in == NULL || out == NULL) {
    return GSEC_ERR_INVALID;
  }
  k = (const unsigned char *)key;
  one_block(k + 2u * GSEC_DES_KEY_LEN, (const unsigned char *)in, block, 1);
  one_block(k + GSEC_DES_KEY_LEN, block, block, 0);
  one_block(k, block, (unsigned char *)out, 1);
  gsec_wipe(block, sizeof block);
  return GSEC_OK;
}

static GSEC_Result cbc(const void * key, size_t key_len, const void * iv,
    const void * in, size_t len, void * out, int ede3, int decrypt) {
  const unsigned char * src;
  unsigned char * dst;
  unsigned char prev[GSEC_DES_BLOCK_LEN];
  unsigned char block[GSEC_DES_BLOCK_LEN];
  size_t off;
  unsigned i;

  if (key == NULL || iv == NULL || key_len !=
      (ede3 ? GSEC_DES_EDE3_KEY_LEN : GSEC_DES_KEY_LEN)) {
    return GSEC_ERR_INVALID;
  }
  if ((len % GSEC_DES_BLOCK_LEN) != 0) {
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
  for (i = 0; i < GSEC_DES_BLOCK_LEN; i++) {
    prev[i] = ((const unsigned char *)iv)[i];
  }
  for (off = 0; off < len; off += GSEC_DES_BLOCK_LEN) {
    if (!decrypt) {
      for (i = 0; i < GSEC_DES_BLOCK_LEN; i++) {
        block[i] = (unsigned char)(src[off + i] ^ prev[i]);
      }
      if (ede3) {
        gsec_des_ede3_encrypt(key, block, dst + off);
      } else {
        gsec_des_encrypt(key, block, dst + off);
      }
      for (i = 0; i < GSEC_DES_BLOCK_LEN; i++) {
        prev[i] = dst[off + i];
      }
    } else {
      for (i = 0; i < GSEC_DES_BLOCK_LEN; i++) {
        block[i] = src[off + i];
      }
      if (ede3) {
        gsec_des_ede3_decrypt(key, block, dst + off);
      } else {
        gsec_des_decrypt(key, block, dst + off);
      }
      for (i = 0; i < GSEC_DES_BLOCK_LEN; i++) {
        dst[off + i] = (unsigned char)(dst[off + i] ^ prev[i]);
        prev[i] = block[i];
      }
    }
  }
  gsec_wipe(prev, sizeof prev);
  gsec_wipe(block, sizeof block);
  return GSEC_OK;
}

GSEC_Result gsec_des_cbc_encrypt(const void * key, const void * iv,
    const void * in, size_t len, void * out) {
  return cbc(key, GSEC_DES_KEY_LEN, iv, in, len, out, 0, 0);
}

GSEC_Result gsec_des_cbc_decrypt(const void * key, const void * iv,
    const void * in, size_t len, void * out) {
  return cbc(key, GSEC_DES_KEY_LEN, iv, in, len, out, 0, 1);
}

GSEC_Result gsec_des_ede3_cbc_encrypt(const void * key, const void * iv,
    const void * in, size_t len, void * out) {
  return cbc(key, GSEC_DES_EDE3_KEY_LEN, iv, in, len, out, 1, 0);
}

GSEC_Result gsec_des_ede3_cbc_decrypt(const void * key, const void * iv,
    const void * in, size_t len, void * out) {
  return cbc(key, GSEC_DES_EDE3_KEY_LEN, iv, in, len, out, 1, 1);
}
