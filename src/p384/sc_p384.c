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
 * Arithmetic modulo the P-384 group order. A 768-bit product is reduced
 * with Barrett. floor(2^768 / n) is 2^384 plus the twelve-limb constant
 * below, and two subtractions of the order bring the remainder into range.
 */

#include "sc_p384.h"

#include <ghoti.io/security/secret.h>

#include <string.h>

static const uint32_t N[12] = {
  0xccc52973u, 0xecec196au, 0x48b0a77au, 0x581a0db2u,
  0xf4372ddfu, 0xc7634d81u, 0xffffffffu, 0xffffffffu,
  0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu
};

static const uint32_t HALF[12] = {
  0x666294b9u, 0x76760cb5u, 0x245853bdu, 0xac0d06d9u,
  0xfa1b96efu, 0xe3b1a6c0u, 0xffffffffu, 0xffffffffu,
  0xffffffffu, 0xffffffffu, 0xffffffffu, 0x7fffffffu
};

static const uint32_t MU[12] = {
  0x333ad68du, 0x1313e695u, 0xb74f5885u, 0xa7e5f24du,
  0x0bc8d220u, 0x389cb27eu, 0x00000000u, 0x00000000u,
  0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u
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

static void csub_m(uint32_t r[13], const uint32_t m[12]) {
  uint32_t tmp[13];
  uint64_t borrow = 0;
  uint32_t mask;
  int i;

  for (i = 0; i < 12; i++) {
    uint64_t t = (uint64_t)r[i] - borrow;
    uint64_t br1 = (uint64_t)(t > r[i]);
    uint64_t d = t - m[i];
    uint64_t br2 = (uint64_t)(d > t);

    tmp[i] = (uint32_t)d;
    borrow = br1 | br2;
  }
  {
    uint64_t t = (uint64_t)r[12] - borrow;

    tmp[12] = (uint32_t)t;
    borrow = (uint64_t)(t > r[12]);
  }
  mask = (uint32_t)0 - (uint32_t)(borrow ^ 1u);
  for (i = 0; i < 13; i++) {
    r[i] ^= mask & (r[i] ^ tmp[i]);
  }
  gsec_wipe(tmp, sizeof tmp);
}

static void mul_mod(uint32_t o[12], const uint32_t a[12], const uint32_t b[12],
    const uint32_t m[12], const uint32_t mu[12]) {
  uint32_t x[24];
  uint32_t prod[36];
  uint32_t q[13];
  uint32_t qn[25];
  uint32_t diff[13];
  uint64_t carry;
  uint64_t borrow;
  int i;

  mul_words(x, a, 12, b, 12);
  mul_words(prod, x, 24, mu, 12);
  carry = 0;
  for (i = 0; i < 12; i++) {
    uint64_t s = (uint64_t)x[12 + i] + (uint64_t)prod[24 + i] + carry;

    q[i] = (uint32_t)s;
    carry = s >> 32;
  }
  q[12] = (uint32_t)carry;
  mul_words(qn, q, 13, m, 12);
  borrow = 0;
  for (i = 0; i < 13; i++) {
    uint32_t xv = (i < 24) ? x[i] : 0;
    uint64_t t = (uint64_t)xv - borrow;
    uint64_t br1 = (uint64_t)(t > xv);
    uint64_t d = t - qn[i];
    uint64_t br2 = (uint64_t)(d > t);

    diff[i] = (uint32_t)d;
    borrow = br1 | br2;
  }
  csub_m(diff, m);
  csub_m(diff, m);
  for (i = 0; i < 12; i++) {
    o[i] = diff[i];
  }
  gsec_wipe(x, sizeof x);
  gsec_wipe(prod, sizeof prod);
  gsec_wipe(q, sizeof q);
  gsec_wipe(qn, sizeof qn);
  gsec_wipe(diff, sizeof diff);
}

void sc_p384_set_bytes(sc_p384 * o, const unsigned char s[48]) {
  int i;

  for (i = 0; i < 12; i++) {
    const unsigned char * p = s + (11 - i) * 4;

    o->v[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
  }
}

void sc_p384_to_bytes(unsigned char out[48], const sc_p384 * n) {
  int i;

  for (i = 0; i < 12; i++) {
    unsigned char * p = out + (11 - i) * 4;

    p[0] = (unsigned char)(n->v[i] >> 24);
    p[1] = (unsigned char)(n->v[i] >> 16);
    p[2] = (unsigned char)(n->v[i] >> 8);
    p[3] = (unsigned char)n->v[i];
  }
}

uint32_t sc_p384_lt_n(const sc_p384 * a) {
  uint64_t borrow = 0;
  int i;

  for (i = 0; i < 12; i++) {
    uint64_t t = (uint64_t)a->v[i] - borrow;
    uint64_t br1 = (uint64_t)(t > a->v[i]);
    uint64_t d = t - N[i];
    uint64_t br2 = (uint64_t)(d > t);

    borrow = br1 | br2;
  }
  return (uint32_t)borrow;
}

void sc_p384_reduce_bytes(sc_p384 * o, const unsigned char s[48]) {
  sc_p384 tmp;
  uint32_t mask;
  uint64_t borrow = 0;
  int i;

  sc_p384_set_bytes(o, s);
  for (i = 0; i < 12; i++) {
    uint64_t t = (uint64_t)o->v[i] - borrow;
    uint64_t br1 = (uint64_t)(t > o->v[i]);
    uint64_t d = t - N[i];
    uint64_t br2 = (uint64_t)(d > t);

    tmp.v[i] = (uint32_t)d;
    borrow = br1 | br2;
  }
  mask = (uint32_t)0 - (uint32_t)(borrow ^ 1u);
  for (i = 0; i < 12; i++) {
    o->v[i] ^= mask & (o->v[i] ^ tmp.v[i]);
  }
  gsec_wipe(&tmp, sizeof tmp);
}

void sc_p384_add(sc_p384 * o, const sc_p384 * a, const sc_p384 * b) {
  uint32_t r[13];
  uint64_t carry = 0;
  int i;

  for (i = 0; i < 12; i++) {
    uint64_t s = (uint64_t)a->v[i] + (uint64_t)b->v[i] + carry;

    r[i] = (uint32_t)s;
    carry = s >> 32;
  }
  r[12] = (uint32_t)carry;
  csub_m(r, N);
  for (i = 0; i < 12; i++) {
    o->v[i] = r[i];
  }
  gsec_wipe(r, sizeof r);
}

void sc_p384_sub(sc_p384 * o, const sc_p384 * a, const sc_p384 * b) {
  uint32_t r[12];
  uint32_t sum[12];
  uint64_t borrow = 0;
  uint64_t carry = 0;
  uint32_t mask;
  int i;

  for (i = 0; i < 12; i++) {
    uint64_t t = (uint64_t)a->v[i] - borrow;
    uint64_t br1 = (uint64_t)(t > a->v[i]);
    uint64_t d = t - b->v[i];
    uint64_t br2 = (uint64_t)(d > t);

    r[i] = (uint32_t)d;
    borrow = br1 | br2;
  }
  for (i = 0; i < 12; i++) {
    uint64_t s = (uint64_t)r[i] + (uint64_t)N[i] + carry;

    sum[i] = (uint32_t)s;
    carry = s >> 32;
  }
  mask = (uint32_t)0 - (uint32_t)borrow;
  for (i = 0; i < 12; i++) {
    o->v[i] = r[i] ^ (mask & (r[i] ^ sum[i]));
  }
  gsec_wipe(r, sizeof r);
  gsec_wipe(sum, sizeof sum);
}

void sc_p384_mul(sc_p384 * o, const sc_p384 * a, const sc_p384 * b) {
  mul_mod(o->v, a->v, b->v, N, MU);
}

void sc_p384_cmov(sc_p384 * o, const sc_p384 * a, uint32_t bit) {
  uint32_t mask = (uint32_t)0 - bit;
  int i;

  for (i = 0; i < 12; i++) {
    o->v[i] ^= mask & (o->v[i] ^ a->v[i]);
  }
}

void sc_p384_inv(sc_p384 * o, const sc_p384 * z) {
  static const uint32_t EXP[12] = {
  0xccc52971u, 0xecec196au, 0x48b0a77au, 0x581a0db2u,
  0xf4372ddfu, 0xc7634d81u, 0xffffffffu, 0xffffffffu,
  0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu
  };
  sc_p384 r;
  sc_p384 base;
  int i;
  int bit;

  memset(&r, 0, sizeof r);
  r.v[0] = 1;
  base = *z;
  for (i = 0; i < 12; i++) {
    for (bit = 0; bit < 32; bit++) {
      if (((EXP[i] >> bit) & 1u) != 0u) {
        sc_p384_mul(&r, &r, &base);
      }
      sc_p384_mul(&base, &base, &base);
    }
  }
  *o = r;
  gsec_wipe(&r, sizeof r);
  gsec_wipe(&base, sizeof base);
}

uint32_t sc_p384_gt_half(const sc_p384 * a) {
  uint32_t gt = 0;
  uint32_t eq = 1;
  int i;

  for (i = 11; i >= 0; i--) {
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
