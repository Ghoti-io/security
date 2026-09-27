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
 * Arithmetic modulo the P-256 group order. A 512-bit product is reduced
 * with Barrett and two subtractions of the order. Both bounds were
 * measured: the remainder is never negative, and two subtractions suffice.
 */

#include "sc_p256.h"

#include <ghoti.io/security/secret.h>

#include <string.h>

/* n, little-endian limbs. */
static const uint32_t N[8] = {
  0xfc632551u, 0xf3b9cac2u, 0xa7179e84u, 0xbce6faadu,
  0xffffffffu, 0xffffffffu, 0x00000000u, 0xffffffffu
};

/* floor(n / 2). Signing replaces s with n - s when s is larger. */
static const uint32_t HALF[8] = {
  0x7e3192a8u, 0x79dce561u, 0xd38bcf42u, 0xde737d56u,
  0xffffffffu, 0x7fffffffu, 0x80000000u, 0x7fffffffu
};

/* Low 256 bits of floor(2^512 / n). The high bit of that quotient is 2^256. */
static const uint32_t MU[8] = {
  0xeedf9bfeu, 0x012ffd85u, 0xdf1a6c21u, 0x43190552u,
  0xffffffffu, 0xfffffffeu, 0xffffffffu, 0x00000000u
};

static void mul_words(uint32_t * c, const uint32_t * a, int na,
    const uint32_t * b, int nb) {
  int i;
  int j;

  for (i = 0; i < na + nb; i++) {
    c[i] = 0;
  }
  for (i = 0; i < na; i++) {
    uint64_t carry = 0;

    for (j = 0; j < nb; j++) {
      uint64_t p = (uint64_t)a[i] * (uint64_t)b[j] + c[i + j] + carry;

      c[i + j] = (uint32_t)p;
      carry = p >> 32;
    }
    c[i + nb] = (uint32_t)carry;
  }
}

static void csub_n9(uint32_t r[9]) {
  uint32_t tmp[9];
  uint64_t borrow = 0;
  uint32_t mask;
  int i;

  for (i = 0; i < 8; i++) {
    uint64_t t = (uint64_t)r[i] - borrow;
    uint64_t br1 = (uint64_t)(t > r[i]);
    uint64_t d = t - N[i];
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
  gsec_wipe(tmp, sizeof tmp);
}

void sc_p256_set_bytes(sc_p256 * o, const unsigned char s[32]) {
  int i;

  for (i = 0; i < 8; i++) {
    const unsigned char * p = s + (7 - i) * 4;

    o->v[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
  }
}

void sc_p256_to_bytes(unsigned char out[32], const sc_p256 * n) {
  int i;

  for (i = 0; i < 8; i++) {
    unsigned char * p = out + (7 - i) * 4;

    p[0] = (unsigned char)(n->v[i] >> 24);
    p[1] = (unsigned char)(n->v[i] >> 16);
    p[2] = (unsigned char)(n->v[i] >> 8);
    p[3] = (unsigned char)n->v[i];
  }
}

uint32_t sc_p256_lt_n(const sc_p256 * a) {
  uint64_t borrow = 0;
  int i;

  for (i = 0; i < 8; i++) {
    uint64_t t = (uint64_t)a->v[i] - borrow;
    uint64_t br1 = (uint64_t)(t > a->v[i]);
    uint64_t d = t - N[i];
    uint64_t br2 = (uint64_t)(d > t);

    borrow = br1 | br2;
  }
  return (uint32_t)borrow;
}

void sc_p256_reduce_bytes(sc_p256 * o, const unsigned char s[32]) {
  sc_p256 tmp;
  uint32_t mask;
  uint64_t borrow = 0;
  int i;

  sc_p256_set_bytes(o, s);
  for (i = 0; i < 8; i++) {
    uint64_t t = (uint64_t)o->v[i] - borrow;
    uint64_t br1 = (uint64_t)(t > o->v[i]);
    uint64_t d = t - N[i];
    uint64_t br2 = (uint64_t)(d > t);

    tmp.v[i] = (uint32_t)d;
    borrow = br1 | br2;
  }
  /* borrow is 1 when the input is already below n. A field element is
   * below 2n, so one subtraction is the whole reduction. */
  mask = (uint32_t)0 - (uint32_t)(borrow ^ 1u);
  for (i = 0; i < 8; i++) {
    o->v[i] ^= mask & (o->v[i] ^ tmp.v[i]);
  }
  gsec_wipe(&tmp, sizeof tmp);
}

void sc_p256_add(sc_p256 * o, const sc_p256 * a, const sc_p256 * b) {
  uint32_t r[9];
  uint64_t carry = 0;
  int i;

  for (i = 0; i < 8; i++) {
    uint64_t s = (uint64_t)a->v[i] + (uint64_t)b->v[i] + carry;

    r[i] = (uint32_t)s;
    carry = s >> 32;
  }
  r[8] = (uint32_t)carry;
  csub_n9(r);
  for (i = 0; i < 8; i++) {
    o->v[i] = r[i];
  }
  gsec_wipe(r, sizeof r);
}

void sc_p256_sub(sc_p256 * o, const sc_p256 * a, const sc_p256 * b) {
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
    uint64_t s = (uint64_t)r[i] + (uint64_t)N[i] + carry;

    sum[i] = (uint32_t)s;
    carry = s >> 32;
  }
  mask = (uint32_t)0 - (uint32_t)borrow;
  for (i = 0; i < 8; i++) {
    o->v[i] = r[i] ^ (mask & (r[i] ^ sum[i]));
  }
  gsec_wipe(r, sizeof r);
  gsec_wipe(sum, sizeof sum);
}

void sc_p256_mul(sc_p256 * o, const sc_p256 * a, const sc_p256 * b) {
  uint32_t x[16];
  uint32_t prod[24];
  uint32_t q[9];
  uint32_t qn[17];
  uint32_t diff[9];
  uint64_t carry;
  uint64_t borrow;
  int i;

  mul_words(x, a->v, 8, b->v, 8);
  mul_words(prod, x, 16, MU, 8);
  carry = 0;
  for (i = 0; i < 8; i++) {
    uint64_t s = (uint64_t)x[8 + i] + (uint64_t)prod[16 + i] + carry;

    q[i] = (uint32_t)s;
    carry = s >> 32;
  }
  q[8] = (uint32_t)carry;
  mul_words(qn, q, 9, N, 8);
  borrow = 0;
  for (i = 0; i < 9; i++) {
    uint32_t xv = (i < 16) ? x[i] : 0;
    uint64_t t = (uint64_t)xv - borrow;
    uint64_t br1 = (uint64_t)(t > xv);
    uint64_t d = t - qn[i];
    uint64_t br2 = (uint64_t)(d > t);

    diff[i] = (uint32_t)d;
    borrow = br1 | br2;
  }
  csub_n9(diff);
  csub_n9(diff);
  for (i = 0; i < 8; i++) {
    o->v[i] = diff[i];
  }
  gsec_wipe(x, sizeof x);
  gsec_wipe(prod, sizeof prod);
  gsec_wipe(q, sizeof q);
  gsec_wipe(qn, sizeof qn);
  gsec_wipe(diff, sizeof diff);
}

void sc_p256_cmov(sc_p256 * o, const sc_p256 * a, uint32_t bit) {
  uint32_t mask = (uint32_t)0 - bit;
  int i;

  for (i = 0; i < 8; i++) {
    o->v[i] ^= mask & (o->v[i] ^ a->v[i]);
  }
}

void sc_p256_inv(sc_p256 * o, const sc_p256 * z) {
  /* n - 2, public. The skipped bits are the exponent, not the base. */
  static const uint32_t EXP[8] = {
    0xfc63254fu, 0xf3b9cac2u, 0xa7179e84u, 0xbce6faadu,
    0xffffffffu, 0xffffffffu, 0x00000000u, 0xffffffffu
  };
  sc_p256 r;
  sc_p256 base;
  int i;
  int b;

  memset(&r, 0, sizeof r);
  r.v[0] = 1;
  base = *z;
  for (i = 0; i < 8; i++) {
    for (b = 0; b < 32; b++) {
      if (((EXP[i] >> b) & 1u) != 0u) {
        sc_p256_mul(&r, &r, &base);
      }
      sc_p256_mul(&base, &base, &base);
    }
  }
  *o = r;
  gsec_wipe(&r, sizeof r);
  gsec_wipe(&base, sizeof base);
}

uint32_t sc_p256_gt_half(const sc_p256 * a) {
  uint32_t gt = 0;
  uint32_t eq = 1;
  int i;

  for (i = 7; i >= 0; i--) {
    uint64_t diff = (uint64_t)a->v[i] - (uint64_t)HALF[i];
    uint32_t below = (uint32_t)(diff >> 32) & 1u;
    uint32_t x = a->v[i] ^ HALF[i];
    uint32_t same;

    x |= x >> 16;
    x |= x >> 8;
    x |= x >> 4;
    x |= x >> 2;
    x |= x >> 1;
    same = (x & 1u) ^ 1u;
    gt |= eq & (below ^ 1u) & (same ^ 1u);
    eq &= same;
  }
  return gt;
}
