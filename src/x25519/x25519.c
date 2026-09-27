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
 * X25519. Field elements are 16 radix-2^16 limbs. The ladder follows RFC
 * 7748 section 5. The addition chain for the inverse is the public
 * exponent p−2. A limb is not a branch condition and not a table index.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/x25519.h>

#include <string.h>

typedef int64_t limb[16];

/* Arithmetic right shift by 16. The sign bit is secret, so the fill is a
 * mask rather than a branch. The mask is the high sixteen bits of the
 * result. Filling from bit 16 up is a sign extension, and a negative limb
 * comes back wrong. */
static int64_t shr16(int64_t v) {
  uint64_t u = (uint64_t)v;
  uint64_t sign = u >> 63;

  return (int64_t)((u >> 16) | (((uint64_t)0 - sign) & UINT64_C(0xffff000000000000)));
}

static void carry(limb o) {
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

static void limb_add(limb o, const limb a, const limb b) {
  int i;

  for (i = 0; i < 16; i++) {
    o[i] = a[i] + b[i];
  }
}

static void limb_sub(limb o, const limb a, const limb b) {
  int i;

  for (i = 0; i < 16; i++) {
    o[i] = a[i] - b[i];
  }
}

static void limb_mul(limb o, const limb a, const limb b) {
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

static void limb_sq(limb o, const limb a) {
  limb_mul(o, a, a);
}

/* Swap if bit is 1. bit is 0 or 1 and is secret. */
static void cswap(limb p, limb q, int bit) {
  uint64_t mask = (uint64_t)0 - (uint64_t)bit;
  int i;

  for (i = 0; i < 16; i++) {
    uint64_t t = mask & ((uint64_t)p[i] ^ (uint64_t)q[i]);

    p[i] = (int64_t)((uint64_t)p[i] ^ t);
    q[i] = (int64_t)((uint64_t)q[i] ^ t);
  }
}

/* z^(p-2). The skipped squarings are the public addition chain. */
static void limb_invert(limb o, const limb z) {
  limb c;
  int a;

  for (a = 0; a < 16; a++) {
    c[a] = z[a];
  }
  for (a = 253; a >= 0; a--) {
    limb_sq(c, c);
    if (a != 2 && a != 4) {
      limb_mul(c, c, z);
    }
  }
  for (a = 0; a < 16; a++) {
    o[a] = c[a];
  }
  gsec_wipe(c, sizeof c);
}

static void from_bytes(limb o, const unsigned char s[32]) {
  int i;

  for (i = 0; i < 16; i++) {
    o[i] = (int64_t)s[2 * i] + ((int64_t)s[2 * i + 1] << 8);
  }
  o[15] &= 0x7fff;
}

static void to_bytes(unsigned char out[32], const limb n) {
  limb t;
  limb m;
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
    cswap(t, m, (int)(1 - b));
  }
  for (i = 0; i < 16; i++) {
    out[2 * i] = (unsigned char)t[i];
    out[2 * i + 1] = (unsigned char)((uint64_t)t[i] >> 8);
  }
  gsec_wipe(t, sizeof t);
  gsec_wipe(m, sizeof m);
}

static void scalarmult(unsigned char out[32], const unsigned char scalar[32],
    const unsigned char point[32]) {
  unsigned char clamped[32];
  limb x1;
  limb x2;
  limb z2;
  limb x3;
  limb z3;
  limb tmp;
  limb e;
  limb f;
  limb a24;
  int i;

  memcpy(clamped, scalar, 32);
  clamped[0] &= 248;
  clamped[31] &= 127;
  clamped[31] |= 64;
  from_bytes(x1, point);
  for (i = 0; i < 16; i++) {
    x2[i] = 0;
    z2[i] = 0;
    x3[i] = x1[i];
    z3[i] = 0;
    a24[i] = 0;
  }
  x2[0] = 1;
  z3[0] = 1;
  a24[0] = 121665;
  for (i = 254; i >= 0; i--) {
    int bit = (clamped[i >> 3] >> (i & 7)) & 1;

    cswap(x2, x3, bit);
    cswap(z2, z3, bit);
    limb_add(e, x2, z2);
    limb_sub(x2, x2, z2);
    limb_add(z2, x3, z3);
    limb_sub(x3, x3, z3);
    limb_sq(z3, e);
    limb_sq(f, x2);
    limb_mul(x2, z2, x2);
    limb_mul(z2, x3, e);
    limb_add(e, x2, z2);
    limb_sub(x2, x2, z2);
    limb_sq(x3, x2);
    limb_sub(z2, z3, f);
    limb_mul(tmp, z2, a24);
    limb_add(tmp, tmp, z3);
    limb_mul(z2, z2, tmp);
    limb_mul(x2, z3, f);
    limb_mul(z3, x3, x1);
    limb_sq(x3, e);
    cswap(x2, x3, bit);
    cswap(z2, z3, bit);
  }
  limb_invert(tmp, z2);
  limb_mul(x2, x2, tmp);
  to_bytes(out, x2);
  gsec_wipe(clamped, sizeof clamped);
  gsec_wipe(x1, sizeof x1);
  gsec_wipe(x2, sizeof x2);
  gsec_wipe(z2, sizeof z2);
  gsec_wipe(x3, sizeof x3);
  gsec_wipe(z3, sizeof z3);
  gsec_wipe(tmp, sizeof tmp);
  gsec_wipe(e, sizeof e);
  gsec_wipe(f, sizeof f);
  gsec_wipe(a24, sizeof a24);
}

static GSEC_Result finish(unsigned char out[32]) {
  static const unsigned char zero[GSEC_X25519_LEN] = {0};
  GSEC_Result same = gsec_equal(out, zero, GSEC_X25519_LEN);

  if (same == GSEC_OK) {
    gsec_wipe(out, GSEC_X25519_LEN);
    return GSEC_ERR_INVALID;
  }
  if (same != GSEC_ERR_MISMATCH) {
    gsec_wipe(out, GSEC_X25519_LEN);
    return same;
  }
  return GSEC_OK;
}

GSEC_Result gsec_x25519(const void * scalar, const void * point, void * out) {
  unsigned char scalar_copy[GSEC_X25519_LEN];
  unsigned char point_copy[GSEC_X25519_LEN];
  unsigned char raw[GSEC_X25519_LEN];
  GSEC_Result result;

  if (scalar == NULL || point == NULL || out == NULL) {
    return GSEC_ERR_INVALID;
  }
  memcpy(scalar_copy, scalar, GSEC_X25519_LEN);
  memcpy(point_copy, point, GSEC_X25519_LEN);
  scalarmult(raw, scalar_copy, point_copy);
  gsec_wipe(scalar_copy, sizeof scalar_copy);
  gsec_wipe(point_copy, sizeof point_copy);
  result = finish(raw);
  if (result == GSEC_OK) {
    memcpy(out, raw, GSEC_X25519_LEN);
  } else {
    gsec_wipe(out, GSEC_X25519_LEN);
  }
  gsec_wipe(raw, sizeof raw);
  return result;
}

GSEC_Result gsec_x25519_public(const void * scalar, void * out) {
  static const unsigned char base[GSEC_X25519_LEN] = {9};

  return gsec_x25519(scalar, base, out);
}
