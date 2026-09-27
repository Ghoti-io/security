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
 * Arithmetic modulo the NIST P-384 prime. A 768-bit product is reduced
 * with Barrett. floor(2^768 / p) is 2^384 plus the twelve-limb constant
 * below, and two subtractions of the prime bring the remainder into range.
 */

#include "fe_p384.h"

#include <ghoti.io/security/secret.h>

#include <string.h>

static const uint32_t P[12] = {
  0xffffffffu, 0x00000000u, 0x00000000u, 0xffffffffu,
  0xfffffffeu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
  0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu
};

static const uint32_t MU[12] = {
  0x00000001u, 0xffffffffu, 0xffffffffu, 0x00000000u,
  0x00000001u, 0x00000000u, 0x00000000u, 0x00000000u,
  0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u
};

const fe_p384 FE_P384_A = {{
  0xfffffffcu, 0x00000000u, 0x00000000u, 0xffffffffu,
  0xfffffffeu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
  0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu
}};

const fe_p384 FE_P384_B = {{
  0xd3ec2aefu, 0x2a85c8edu, 0x8a2ed19du, 0xc656398du,
  0x5013875au, 0x0314088fu, 0xfe814112u, 0x181d9c6eu,
  0xe3f82d19u, 0x988e056bu, 0xe23ee7e4u, 0xb3312fa7u
}};

const fe_p384 FE_P384_B3 = {{
  0x7bc480cfu, 0x7f915ac7u, 0x9e8c74d7u, 0x5302acaau,
  0xf03a9612u, 0x093c19adu, 0xfb83c336u, 0x4858d54cu,
  0xabe8874bu, 0xc9aa1043u, 0xa6bcb7adu, 0x19938ef7u
}};

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

void fe_p384_mul(fe_p384 * o, const fe_p384 * a, const fe_p384 * b) {
  mul_mod(o->v, a->v, b->v, P, MU);
}

void fe_p384_add(fe_p384 * o, const fe_p384 * a, const fe_p384 * b) {
  uint32_t r[13];
  uint64_t carry = 0;
  int i;

  for (i = 0; i < 12; i++) {
    uint64_t s = (uint64_t)a->v[i] + (uint64_t)b->v[i] + carry;

    r[i] = (uint32_t)s;
    carry = s >> 32;
  }
  r[12] = (uint32_t)carry;
  csub_m(r, P);
  for (i = 0; i < 12; i++) {
    o->v[i] = r[i];
  }
  gsec_wipe(r, sizeof r);
}

void fe_p384_sub(fe_p384 * o, const fe_p384 * a, const fe_p384 * b) {
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
    uint64_t s = (uint64_t)r[i] + (uint64_t)P[i] + carry;

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

void fe_p384_cmov(fe_p384 * o, const fe_p384 * a, int bit) {
  uint32_t mask = (uint32_t)0 - (uint32_t)bit;
  int i;

  for (i = 0; i < 12; i++) {
    o->v[i] ^= mask & (o->v[i] ^ a->v[i]);
  }
}

void fe_p384_set_u32(fe_p384 * o, uint32_t x) {
  int i;

  o->v[0] = x;
  for (i = 1; i < 12; i++) {
    o->v[i] = 0;
  }
}

void fe_p384_inv(fe_p384 * o, const fe_p384 * z) {
  static const uint32_t EXP[12] = {
  0xfffffffdu, 0x00000000u, 0x00000000u, 0xffffffffu,
  0xfffffffeu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
  0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu
  };
  fe_p384 r;
  fe_p384 base;
  int i;
  int b;

  fe_p384_set_u32(&r, 1);
  base = *z;
  for (i = 0; i < 12; i++) {
    for (b = 0; b < 32; b++) {
      if (((EXP[i] >> b) & 1u) != 0u) {
        fe_p384_mul(&r, &r, &base);
      }
      fe_p384_mul(&base, &base, &base);
    }
  }
  *o = r;
  gsec_wipe(&r, sizeof r);
  gsec_wipe(&base, sizeof base);
}

int fe_p384_from_bytes(fe_p384 * o, const unsigned char s[48]) {
  int i;

  for (i = 0; i < 12; i++) {
    const unsigned char * p = s + (11 - i) * 4;

    o->v[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
  }
  for (i = 11; i >= 0; i--) {
    if (o->v[i] < P[i]) {
      return 1;
    }
    if (o->v[i] > P[i]) {
      return 0;
    }
  }
  return 0;
}

void fe_p384_to_bytes(unsigned char out[48], const fe_p384 * n) {
  int i;

  for (i = 0; i < 12; i++) {
    unsigned char * p = out + (11 - i) * 4;

    p[0] = (unsigned char)(n->v[i] >> 24);
    p[1] = (unsigned char)(n->v[i] >> 16);
    p[2] = (unsigned char)(n->v[i] >> 8);
    p[3] = (unsigned char)n->v[i];
  }
}
