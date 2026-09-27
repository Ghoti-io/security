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
 * X25519. The ladder follows RFC 7748 section 5. The field is
 * src/curve25519/fe25519.c, shared with Ed25519.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/x25519.h>

#include "../curve25519/fe25519.h"

#include <string.h>

static void scalarmult(unsigned char out[32], const unsigned char scalar[32],
    const unsigned char point[32]) {
  unsigned char clamped[32];
  fe25519 x1;
  fe25519 x2;
  fe25519 z2;
  fe25519 x3;
  fe25519 z3;
  fe25519 tmp;
  fe25519 e;
  fe25519 f;
  fe25519 a24;
  int i;

  memcpy(clamped, scalar, 32);
  clamped[0] &= 248;
  clamped[31] &= 127;
  clamped[31] |= 64;
  fe25519_from_bytes(x1, point);
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

    fe25519_cswap(x2, x3, bit);
    fe25519_cswap(z2, z3, bit);
    fe25519_add(e, x2, z2);
    fe25519_sub(x2, x2, z2);
    fe25519_add(z2, x3, z3);
    fe25519_sub(x3, x3, z3);
    fe25519_sq(z3, e);
    fe25519_sq(f, x2);
    fe25519_mul(x2, z2, x2);
    fe25519_mul(z2, x3, e);
    fe25519_add(e, x2, z2);
    fe25519_sub(x2, x2, z2);
    fe25519_sq(x3, x2);
    fe25519_sub(z2, z3, f);
    fe25519_mul(tmp, z2, a24);
    fe25519_add(tmp, tmp, z3);
    fe25519_mul(z2, z2, tmp);
    fe25519_mul(x2, z3, f);
    fe25519_mul(z3, x3, x1);
    fe25519_sq(x3, e);
    fe25519_cswap(x2, x3, bit);
    fe25519_cswap(z2, z3, bit);
  }
  fe25519_invert(tmp, z2);
  fe25519_mul(x2, x2, tmp);
  fe25519_to_bytes(out, x2);
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
