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
 * Complete projective addition on P-256, from Renes, Costello, and Batina.
 * The scalar loop always adds and always doubles. The bit only chooses
 * which sum is kept.
 */

#include "p256_point.h"

#include <ghoti.io/security/secret.h>

#include <string.h>

static const fe_p256 BASE_X = {{
  0xd898c296u, 0xf4a13945u, 0x2deb33a0u, 0x77037d81u,
  0x63a440f2u, 0xf8bce6e5u, 0xe12c4247u, 0x6b17d1f2u
}};

static const fe_p256 BASE_Y = {{
  0x37bf51f5u, 0xcbb64068u, 0x6b315eceu, 0x2bce3357u,
  0x7c0f9e16u, 0x8ee7eb4au, 0xfe1a7f9bu, 0x4fe342e2u
}};

static void point_set_identity(p256_point * p) {
  fe_p256_set_u32(&p->x, 0);
  fe_p256_set_u32(&p->y, 1);
  fe_p256_set_u32(&p->z, 0);
}

static void point_cmov(p256_point * o, const p256_point * a, int bit) {
  fe_p256_cmov(&o->x, &a->x, bit);
  fe_p256_cmov(&o->y, &a->y, bit);
  fe_p256_cmov(&o->z, &a->z, bit);
}

static void point_add(p256_point * o, const p256_point * p, const p256_point * q) {
  fe_p256 t0;
  fe_p256 t1;
  fe_p256 t2;
  fe_p256 t3;
  fe_p256 t4;
  fe_p256 t5;
  fe_p256 x3;
  fe_p256 y3;
  fe_p256 z3;

  fe_p256_mul(&t0, &p->x, &q->x);
  fe_p256_mul(&t1, &p->y, &q->y);
  fe_p256_mul(&t2, &p->z, &q->z);
  fe_p256_add(&t3, &p->x, &p->y);
  fe_p256_add(&t4, &q->x, &q->y);
  fe_p256_mul(&t3, &t3, &t4);
  fe_p256_add(&t4, &t0, &t1);
  fe_p256_sub(&t3, &t3, &t4);
  fe_p256_add(&t4, &p->x, &p->z);
  fe_p256_add(&t5, &q->x, &q->z);
  fe_p256_mul(&t4, &t4, &t5);
  fe_p256_add(&t5, &t0, &t2);
  fe_p256_sub(&t4, &t4, &t5);
  fe_p256_add(&t5, &p->y, &p->z);
  fe_p256_add(&x3, &q->y, &q->z);
  fe_p256_mul(&t5, &t5, &x3);
  fe_p256_add(&x3, &t1, &t2);
  fe_p256_sub(&t5, &t5, &x3);
  fe_p256_mul(&z3, &FE_P256_A, &t4);
  fe_p256_mul(&x3, &FE_P256_B3, &t2);
  fe_p256_add(&z3, &x3, &z3);
  fe_p256_sub(&x3, &t1, &z3);
  fe_p256_add(&z3, &t1, &z3);
  fe_p256_mul(&y3, &x3, &z3);
  fe_p256_add(&t1, &t0, &t0);
  fe_p256_add(&t1, &t1, &t0);
  fe_p256_mul(&t2, &FE_P256_A, &t2);
  fe_p256_mul(&t4, &FE_P256_B3, &t4);
  fe_p256_add(&t1, &t1, &t2);
  fe_p256_sub(&t2, &t0, &t2);
  fe_p256_mul(&t2, &FE_P256_A, &t2);
  fe_p256_add(&t4, &t4, &t2);
  fe_p256_mul(&t0, &t1, &t4);
  fe_p256_add(&y3, &y3, &t0);
  fe_p256_mul(&t0, &t5, &t4);
  fe_p256_mul(&x3, &t3, &x3);
  fe_p256_sub(&x3, &x3, &t0);
  fe_p256_mul(&t0, &t3, &t1);
  fe_p256_mul(&z3, &t5, &z3);
  fe_p256_add(&z3, &z3, &t0);
  o->x = x3;
  o->y = y3;
  o->z = z3;
  gsec_wipe(&t0, sizeof t0);
  gsec_wipe(&t1, sizeof t1);
  gsec_wipe(&t2, sizeof t2);
  gsec_wipe(&t3, sizeof t3);
  gsec_wipe(&t4, sizeof t4);
  gsec_wipe(&t5, sizeof t5);
  gsec_wipe(&x3, sizeof x3);
  gsec_wipe(&y3, sizeof y3);
  gsec_wipe(&z3, sizeof z3);
}

static int on_curve(const fe_p256 * x, const fe_p256 * y) {
  fe_p256 y2;
  fe_p256 x2;
  fe_p256 x3;
  fe_p256 ax;
  fe_p256 rhs;
  unsigned char left[32];
  unsigned char right[32];
  int ok;

  fe_p256_mul(&y2, y, y);
  fe_p256_mul(&x2, x, x);
  fe_p256_mul(&x3, &x2, x);
  fe_p256_mul(&ax, &FE_P256_A, x);
  fe_p256_add(&rhs, &x3, &ax);
  fe_p256_add(&rhs, &rhs, &FE_P256_B);
  fe_p256_to_bytes(left, &y2);
  fe_p256_to_bytes(right, &rhs);
  ok = gsec_equal(left, right, 32) == GSEC_OK;
  gsec_wipe(&y2, sizeof y2);
  gsec_wipe(&x2, sizeof x2);
  gsec_wipe(&x3, sizeof x3);
  gsec_wipe(&ax, sizeof ax);
  gsec_wipe(&rhs, sizeof rhs);
  gsec_wipe(left, sizeof left);
  gsec_wipe(right, sizeof right);
  return ok;
}

int p256_point_decode(p256_point * p, const unsigned char xy[64]) {
  if (!fe_p256_from_bytes(&p->x, xy) || !fe_p256_from_bytes(&p->y, xy + 32)) {
    return 0;
  }
  if (!on_curve(&p->x, &p->y)) {
    return 0;
  }
  fe_p256_set_u32(&p->z, 1);
  return 1;
}

static int affine(fe_p256 * x_out, fe_p256 * y_out, const p256_point * p) {
  unsigned char zb[32];
  unsigned char zero[32];
  fe_p256 inv;
  int infinity;
  int i;

  for (i = 0; i < 32; i++) {
    zero[i] = 0;
  }
  fe_p256_to_bytes(zb, &p->z);
  infinity = gsec_equal(zb, zero, 32) == GSEC_OK;
  fe_p256_inv(&inv, &p->z);
  fe_p256_mul(x_out, &p->x, &inv);
  fe_p256_mul(y_out, &p->y, &inv);
  gsec_wipe(&inv, sizeof inv);
  gsec_wipe(zb, sizeof zb);
  if (infinity) {
    gsec_wipe(x_out, sizeof *x_out);
    gsec_wipe(y_out, sizeof *y_out);
    return 0;
  }
  return 1;
}

int p256_scalarmult(fe_p256 * x_out, fe_p256 * y_out,
    const unsigned char scalar[32], const p256_point * base) {
  p256_point r;
  p256_point q;
  p256_point sum;
  int i;
  int ok;

  point_set_identity(&r);
  q = *base;
  for (i = 0; i < 256; i++) {
    int bit = (scalar[31 - (i >> 3)] >> (i & 7)) & 1;

    point_add(&sum, &r, &q);
    point_cmov(&r, &sum, bit);
    point_add(&q, &q, &q);
  }
  ok = affine(x_out, y_out, &r);
  gsec_wipe(&r, sizeof r);
  gsec_wipe(&q, sizeof q);
  gsec_wipe(&sum, sizeof sum);
  return ok;
}

int p256_scalarmult_base(fe_p256 * x_out, fe_p256 * y_out,
    const unsigned char scalar[32]) {
  p256_point base;

  base.x = BASE_X;
  base.y = BASE_Y;
  fe_p256_set_u32(&base.z, 1);
  return p256_scalarmult(x_out, y_out, scalar, &base);
}
