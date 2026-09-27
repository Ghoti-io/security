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
 * Arithmetic modulo 2^255−19. The inverse is the public exponent p−2.
 * A product is accumulated in a temporary, so the output may alias an
 * input. A negative carry is multiplied by 2^16: shifting it would be
 * undefined.
 */

#include "fe25519.h"

#include <ghoti.io/security/secret.h>

/* Arithmetic right shift by 16. The sign bit is secret, so the fill is a
 * mask rather than a branch. The mask is the high sixteen bits of the
 * result. */
static int64_t shr16(int64_t v) {
  uint64_t u = (uint64_t)v;
  uint64_t sign = u >> 63;

  return (int64_t)((u >> 16) | (((uint64_t)0 - sign) & UINT64_C(0xffff000000000000)));
}

static void carry(fe25519 o) {
  int i;

  for (i = 0; i < 16; i++) {
    int64_t c;

    o[i] += (int64_t)1 << 16;
    c = shr16(o[i]);
    o[i] -= c * ((int64_t)1 << 16);
    if (i < 15) {
      o[i + 1] += c - 1;
    } else {
      o[0] += 38 * (c - 1);
    }
  }
}

void fe25519_add(fe25519 o, const fe25519 a, const fe25519 b) {
  int i;

  for (i = 0; i < 16; i++) {
    o[i] = a[i] + b[i];
  }
}

void fe25519_sub(fe25519 o, const fe25519 a, const fe25519 b) {
  int i;

  for (i = 0; i < 16; i++) {
    o[i] = a[i] - b[i];
  }
}

void fe25519_mul(fe25519 o, const fe25519 a, const fe25519 b) {
  int64_t t[31];
  int i;
  int j;

  for (i = 0; i < 31; i++) {
    t[i] = 0;
  }
  for (i = 0; i < 16; i++) {
    for (j = 0; j < 16; j++) {
      t[i + j] += a[i] * b[j];
    }
  }
  for (i = 16; i < 31; i++) {
    t[i - 16] += 38 * t[i];
  }
  for (i = 0; i < 16; i++) {
    o[i] = t[i];
  }
  carry(o);
  carry(o);
}

void fe25519_sq(fe25519 o, const fe25519 a) {
  fe25519_mul(o, a, a);
}

void fe25519_cswap(fe25519 p, fe25519 q, int bit) {
  uint64_t mask = (uint64_t)0 - (uint64_t)bit;
  int i;

  for (i = 0; i < 16; i++) {
    uint64_t t = mask & ((uint64_t)p[i] ^ (uint64_t)q[i]);

    p[i] = (int64_t)((uint64_t)p[i] ^ t);
    q[i] = (int64_t)((uint64_t)q[i] ^ t);
  }
}

void fe25519_cmov(fe25519 o, const fe25519 a, int bit) {
  uint64_t mask = (uint64_t)0 - (uint64_t)bit;
  int i;

  for (i = 0; i < 16; i++) {
    uint64_t x = (uint64_t)o[i];

    o[i] = (int64_t)(x ^ (mask & (x ^ (uint64_t)a[i])));
  }
}

void fe25519_invert(fe25519 o, const fe25519 z) {
  fe25519 c;
  int a;

  for (a = 0; a < 16; a++) {
    c[a] = z[a];
  }
  for (a = 253; a >= 0; a--) {
    fe25519_sq(c, c);
    if (a != 2 && a != 4) {
      fe25519_mul(c, c, z);
    }
  }
  for (a = 0; a < 16; a++) {
    o[a] = c[a];
  }
  gsec_wipe(c, sizeof c);
}

void fe25519_from_bytes(fe25519 o, const unsigned char s[32]) {
  int i;

  for (i = 0; i < 16; i++) {
    o[i] = (int64_t)s[2 * i] + ((int64_t)s[2 * i + 1] << 8);
  }
  o[15] &= 0x7fff;
}

void fe25519_to_bytes(unsigned char out[32], const fe25519 n) {
  fe25519 t;
  fe25519 m;
  int i;
  int j;

  for (i = 0; i < 16; i++) {
    t[i] = n[i];
  }
  carry(t);
  carry(t);
  carry(t);
  for (j = 0; j < 2; j++) {
    int64_t b;

    m[0] = t[0] - 0xffed;
    for (i = 1; i < 15; i++) {
      m[i] = t[i] - 0xffff - (shr16(m[i - 1]) & 1);
      m[i - 1] = (int64_t)((uint64_t)m[i - 1] & 0xffffu);
    }
    m[15] = t[15] - 0x7fff - (shr16(m[14]) & 1);
    b = shr16(m[15]) & 1;
    m[14] = (int64_t)((uint64_t)m[14] & 0xffffu);
    fe25519_cswap(t, m, (int)(1 - b));
  }
  for (i = 0; i < 16; i++) {
    out[2 * i] = (unsigned char)t[i];
    out[2 * i + 1] = (unsigned char)((uint64_t)t[i] >> 8);
  }
  gsec_wipe(t, sizeof t);
  gsec_wipe(m, sizeof m);
}
