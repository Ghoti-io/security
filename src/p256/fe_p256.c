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
 * Arithmetic modulo the NIST P-256 prime. A product is reduced with the
 * Solinas identity and a fixed number of subtractions of the prime. A
 * negative carry is multiplied by 2^32: shifting it would be undefined.
 */

#include "fe_p256.h"

#include <ghoti.io/security/secret.h>

#include <string.h>

/* p = 2^256 − 2^224 + 2^192 + 2^96 − 1, little-endian limbs. */
static const uint32_t P[8] = {
  0xffffffffu, 0xffffffffu, 0xffffffffu, 0x00000000u,
  0x00000000u, 0x00000000u, 0x00000001u, 0xffffffffu
};

/* 4p, nine limbs. Added to a signed reduction so the result is positive. */
static const uint32_t P4[9] = {
  0xfffffffcu, 0xffffffffu, 0xffffffffu, 0x00000003u,
  0x00000000u, 0x00000000u, 0x00000004u, 0xfffffffcu,
  0x00000003u
};

const fe_p256 FE_P256_A = {{
  0xfffffffcu, 0xffffffffu, 0xffffffffu, 0x00000000u,
  0x00000000u, 0x00000000u, 0x00000001u, 0xffffffffu
}};

const fe_p256 FE_P256_B = {{
  0x27d2604bu, 0x3bce3c3eu, 0xcc53b0f6u, 0x651d06b0u,
  0x769886bcu, 0xb3ebbd55u, 0xaa3a93e7u, 0x5ac635d8u
}};

const fe_p256 FE_P256_B3 = {{
  0x777720e2u, 0xb36ab4bau, 0x64fb12e2u, 0x2f571411u,
  0x63c99435u, 0x1bc33800u, 0xfeafbbb6u, 0x1052a18au
}};

/* Floor division by 2^32. The sign bit is secret, so the fill is a mask.
 * The mask is the high 32 bits of the result. */
static int64_t shr32(int64_t v) {
  uint64_t u = (uint64_t)v;
  uint64_t sign = u >> 63;

  return (int64_t)((u >> 32) |
      (((uint64_t)0 - sign) & UINT64_C(0xffffffff00000000)));
}

static void csub_p9(uint32_t r[9]) {
  uint32_t tmp[9];
  uint64_t borrow = 0;
  uint32_t mask;
  int i;

  for (i = 0; i < 8; i++) {
    uint64_t t = (uint64_t)r[i] - borrow;
    uint64_t br1 = (uint64_t)(t > r[i]);
    uint64_t d = t - P[i];
    uint64_t br2 = (uint64_t)(d > t);

    tmp[i] = (uint32_t)d;
    borrow = br1 | br2;
  }
  {
    uint64_t t = (uint64_t)r[8] - borrow;

    tmp[8] = (uint32_t)t;
    borrow = (uint64_t)(t > r[8]);
  }
  mask = (uint32_t)0 - (uint32_t)(borrow ^ 1u);
  for (i = 0; i < 9; i++) {
    r[i] ^= mask & (r[i] ^ tmp[i]);
  }
}

static void add_limb(int64_t w[12], int idx, uint32_t word, int scale) {
  w[idx] += (int64_t)scale * (int64_t)word;
}

static void carry_signed(int64_t w[12]) {
  int i;

  for (i = 0; i < 11; i++) {
    int64_t c = shr32(w[i]);

    w[i] -= c * ((int64_t)1 << 32);
    w[i + 1] += c;
  }
}

void fe_p256_mul(fe_p256 * o, const fe_p256 * a, const fe_p256 * b) {
  uint32_t c[16];
  int64_t w[12];
  uint32_t r[9];
  uint64_t carry;
  int i;
  int j;

  for (i = 0; i < 16; i++) {
    c[i] = 0;
  }
  for (i = 0; i < 8; i++) {
    carry = 0;
    for (j = 0; j < 8; j++) {
      uint64_t p = (uint64_t)a->v[i] * (uint64_t)b->v[j] + c[i + j] + carry;

      c[i + j] = (uint32_t)p;
      carry = p >> 32;
    }
    c[i + 8] = (uint32_t)carry;
  }
  for (i = 0; i < 12; i++) {
    w[i] = 0;
  }
  for (i = 0; i < 8; i++) {
    add_limb(w, i, c[i], 1);
  }
  add_limb(w, 3, c[11], 2);
  add_limb(w, 4, c[12], 2);
  add_limb(w, 5, c[13], 2);
  add_limb(w, 6, c[14], 2);
  add_limb(w, 7, c[15], 2);
  add_limb(w, 3, c[12], 2);
  add_limb(w, 4, c[13], 2);
  add_limb(w, 5, c[14], 2);
  add_limb(w, 6, c[15], 2);
  add_limb(w, 0, c[8], 1);
  add_limb(w, 1, c[9], 1);
  add_limb(w, 2, c[10], 1);
  add_limb(w, 6, c[14], 1);
  add_limb(w, 7, c[15], 1);
  add_limb(w, 0, c[9], 1);
  add_limb(w, 1, c[10], 1);
  add_limb(w, 2, c[11], 1);
  add_limb(w, 3, c[13], 1);
  add_limb(w, 4, c[14], 1);
  add_limb(w, 5, c[15], 1);
  add_limb(w, 6, c[13], 1);
  add_limb(w, 7, c[8], 1);
  add_limb(w, 0, c[11], -1);
  add_limb(w, 1, c[12], -1);
  add_limb(w, 2, c[13], -1);
  add_limb(w, 6, c[8], -1);
  add_limb(w, 7, c[10], -1);
  add_limb(w, 0, c[12], -1);
  add_limb(w, 1, c[13], -1);
  add_limb(w, 2, c[14], -1);
  add_limb(w, 3, c[15], -1);
  add_limb(w, 6, c[9], -1);
  add_limb(w, 7, c[11], -1);
  add_limb(w, 0, c[13], -1);
  add_limb(w, 1, c[14], -1);
  add_limb(w, 2, c[15], -1);
  add_limb(w, 3, c[8], -1);
  add_limb(w, 4, c[9], -1);
  add_limb(w, 5, c[10], -1);
  add_limb(w, 7, c[12], -1);
  add_limb(w, 0, c[14], -1);
  add_limb(w, 1, c[15], -1);
  add_limb(w, 3, c[9], -1);
  add_limb(w, 4, c[10], -1);
  add_limb(w, 5, c[11], -1);
  add_limb(w, 7, c[13], -1);
  carry_signed(w);
  for (i = 0; i < 9; i++) {
    w[i] += P4[i];
  }
  carry_signed(w);
  for (i = 0; i < 9; i++) {
    r[i] = (uint32_t)w[i];
  }
  for (i = 0; i < 8; i++) {
    csub_p9(r);
  }
  for (i = 0; i < 8; i++) {
    o->v[i] = r[i];
  }
  gsec_wipe(c, sizeof c);
  gsec_wipe(w, sizeof w);
  gsec_wipe(r, sizeof r);
}

void fe_p256_add(fe_p256 * o, const fe_p256 * a, const fe_p256 * b) {
  uint32_t r[9];
  uint64_t carry = 0;
  int i;

  for (i = 0; i < 8; i++) {
    uint64_t s = (uint64_t)a->v[i] + (uint64_t)b->v[i] + carry;

    r[i] = (uint32_t)s;
    carry = s >> 32;
  }
  r[8] = (uint32_t)carry;
  csub_p9(r);
  for (i = 0; i < 8; i++) {
    o->v[i] = r[i];
  }
}

void fe_p256_sub(fe_p256 * o, const fe_p256 * a, const fe_p256 * b) {
  uint32_t r[8];
  uint32_t sum[8];
  uint64_t borrow = 0;
  uint64_t carry = 0;
  uint32_t mask;
  int i;

  for (i = 0; i < 8; i++) {
    uint64_t t = (uint64_t)a->v[i] - borrow;
    uint64_t br1 = (uint64_t)(t > a->v[i]);
    uint64_t d = t - b->v[i];
    uint64_t br2 = (uint64_t)(d > t);

    r[i] = (uint32_t)d;
    borrow = br1 | br2;
  }
  for (i = 0; i < 8; i++) {
    uint64_t s = (uint64_t)r[i] + (uint64_t)P[i] + carry;

    sum[i] = (uint32_t)s;
    carry = s >> 32;
  }
  mask = (uint32_t)0 - (uint32_t)borrow;
  for (i = 0; i < 8; i++) {
    o->v[i] = r[i] ^ (mask & (r[i] ^ sum[i]));
  }
}

void fe_p256_cmov(fe_p256 * o, const fe_p256 * a, int bit) {
  uint32_t mask = (uint32_t)0 - (uint32_t)bit;
  int i;

  for (i = 0; i < 8; i++) {
    o->v[i] ^= mask & (o->v[i] ^ a->v[i]);
  }
}

void fe_p256_set_u32(fe_p256 * o, uint32_t x) {
  int i;

  o->v[0] = x;
  for (i = 1; i < 8; i++) {
    o->v[i] = 0;
  }
}

void fe_p256_inv(fe_p256 * o, const fe_p256 * z) {
  /* p − 2, public. The skipped bits are the exponent, not the base. */
  static const uint32_t EXP[8] = {
    0xfffffffdu, 0xffffffffu, 0xffffffffu, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000001u, 0xffffffffu
  };
  fe_p256 r;
  fe_p256 base;
  int i;
  int b;

  fe_p256_set_u32(&r, 1);
  base = *z;
  for (i = 0; i < 8; i++) {
    for (b = 0; b < 32; b++) {
      if (((EXP[i] >> b) & 1u) != 0u) {
        fe_p256_mul(&r, &r, &base);
      }
      fe_p256_mul(&base, &base, &base);
    }
  }
  *o = r;
  gsec_wipe(&r, sizeof r);
  gsec_wipe(&base, sizeof base);
}

int fe_p256_from_bytes(fe_p256 * o, const unsigned char s[32]) {
  int i;

  for (i = 0; i < 8; i++) {
    const unsigned char * p = s + (7 - i) * 4;

    o->v[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
  }
  for (i = 7; i >= 0; i--) {
    if (o->v[i] < P[i]) {
      return 1;
    }
    if (o->v[i] > P[i]) {
      return 0;
    }
  }
  return 0;
}

void fe_p256_to_bytes(unsigned char out[32], const fe_p256 * n) {
  int i;

  for (i = 0; i < 8; i++) {
    unsigned char * p = out + (7 - i) * 4;

    p[0] = (unsigned char)(n->v[i] >> 24);
    p[1] = (unsigned char)(n->v[i] >> 16);
    p[2] = (unsigned char)(n->v[i] >> 8);
    p[3] = (unsigned char)n->v[i];
  }
}
