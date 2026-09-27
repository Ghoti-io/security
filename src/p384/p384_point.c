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
 * Complete projective addition on P-384, from Renes, Costello, and Batina.
 * The scalar loop always adds and always doubles. The bit only chooses
 * which sum is kept.
 */

#include "p384_point.h"

#include <ghoti.io/security/secret.h>

#include <string.h>

static const fe_p384 BASE_X = {{
  0x72760ab7u, 0x3a545e38u, 0xbf55296cu, 0x5502f25du,
  0x82542a38u, 0x59f741e0u, 0x8ba79b98u, 0x6e1d3b62u,
  0xf320ad74u, 0x8eb1c71eu, 0xbe8b0537u, 0xaa87ca22u
}};

static const fe_p384 BASE_Y = {{
  0x90ea0e5fu, 0x7a431d7cu, 0x1d7e819du, 0x0a60b1ceu,
  0xb5f0b8c0u, 0xe9da3113u, 0x289a147cu, 0xf8f41dbdu,
  0x9292dc29u, 0x5d9e98bfu, 0x96262c6fu, 0x3617de4au
}};

static void point_set_identity(p384_point * p) {
  fe_p384_set_u32(&p->x, 0);
  fe_p384_set_u32(&p->y, 1);
  fe_p384_set_u32(&p->z, 0);
}

static void point_cmov(p384_point * o, const p384_point * a, int bit) {
  fe_p384_cmov(&o->x, &a->x, bit);
  fe_p384_cmov(&o->y, &a->y, bit);
  fe_p384_cmov(&o->z, &a->z, bit);
}

static void point_add(p384_point * o, const p384_point * p, const p384_point * q) {
  fe_p384 t0;
  fe_p384 t1;
  fe_p384 t2;
  fe_p384 t3;
  fe_p384 t4;
  fe_p384 t5;
  fe_p384 x3;
  fe_p384 y3;
  fe_p384 z3;

  fe_p384_mul(&t0, &p->x, &q->x);
  fe_p384_mul(&t1, &p->y, &q->y);
  fe_p384_mul(&t2, &p->z, &q->z);
  fe_p384_add(&t3, &p->x, &p->y);
  fe_p384_add(&t4, &q->x, &q->y);
  fe_p384_mul(&t3, &t3, &t4);
  fe_p384_add(&t4, &t0, &t1);
  fe_p384_sub(&t3, &t3, &t4);
  fe_p384_add(&t4, &p->x, &p->z);
  fe_p384_add(&t5, &q->x, &q->z);
  fe_p384_mul(&t4, &t4, &t5);
  fe_p384_add(&t5, &t0, &t2);
  fe_p384_sub(&t4, &t4, &t5);
  fe_p384_add(&t5, &p->y, &p->z);
  fe_p384_add(&x3, &q->y, &q->z);
  fe_p384_mul(&t5, &t5, &x3);
  fe_p384_add(&x3, &t1, &t2);
  fe_p384_sub(&t5, &t5, &x3);
  fe_p384_mul(&z3, &FE_P384_A, &t4);
  fe_p384_mul(&x3, &FE_P384_B3, &t2);
  fe_p384_add(&z3, &x3, &z3);
  fe_p384_sub(&x3, &t1, &z3);
  fe_p384_add(&z3, &t1, &z3);
  fe_p384_mul(&y3, &x3, &z3);
  fe_p384_add(&t1, &t0, &t0);
  fe_p384_add(&t1, &t1, &t0);
  fe_p384_mul(&t2, &FE_P384_A, &t2);
  fe_p384_mul(&t4, &FE_P384_B3, &t4);
  fe_p384_add(&t1, &t1, &t2);
  fe_p384_sub(&t2, &t0, &t2);
  fe_p384_mul(&t2, &FE_P384_A, &t2);
  fe_p384_add(&t4, &t4, &t2);
  fe_p384_mul(&t0, &t1, &t4);
  fe_p384_add(&y3, &y3, &t0);
  fe_p384_mul(&t0, &t5, &t4);
  fe_p384_mul(&x3, &t3, &x3);
  fe_p384_sub(&x3, &x3, &t0);
  fe_p384_mul(&t0, &t3, &t1);
  fe_p384_mul(&z3, &t5, &z3);
  fe_p384_add(&z3, &z3, &t0);
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

static int on_curve(const fe_p384 * x, const fe_p384 * y) {
  fe_p384 y2;
  fe_p384 x2;
  fe_p384 x3;
  fe_p384 ax;
  fe_p384 rhs;
  unsigned char left[48];
  unsigned char right[48];
  int ok;

  fe_p384_mul(&y2, y, y);
  fe_p384_mul(&x2, x, x);
  fe_p384_mul(&x3, &x2, x);
  fe_p384_mul(&ax, &FE_P384_A, x);
  fe_p384_add(&rhs, &x3, &ax);
  fe_p384_add(&rhs, &rhs, &FE_P384_B);
  fe_p384_to_bytes(left, &y2);
  fe_p384_to_bytes(right, &rhs);
  ok = gsec_equal(left, right, 48) == GSEC_OK;
  gsec_wipe(&y2, sizeof y2);
  gsec_wipe(&x2, sizeof x2);
  gsec_wipe(&x3, sizeof x3);
  gsec_wipe(&ax, sizeof ax);
  gsec_wipe(&rhs, sizeof rhs);
  gsec_wipe(left, sizeof left);
  gsec_wipe(right, sizeof right);
  return ok;
}

int p384_point_decode(p384_point * p, const unsigned char xy[96]) {
  if (!fe_p384_from_bytes(&p->x, xy) || !fe_p384_from_bytes(&p->y, xy + 48)) {
    return 0;
  }
  if (!on_curve(&p->x, &p->y)) {
    return 0;
  }
  fe_p384_set_u32(&p->z, 1);
  return 1;
}

static int affine(fe_p384 * x_out, fe_p384 * y_out, const p384_point * p) {
  unsigned char zb[48];
  unsigned char zero[48];
  fe_p384 inv;
  int infinity;
  int i;

  for (i = 0; i < 48; i++) {
    zero[i] = 0;
  }
  fe_p384_to_bytes(zb, &p->z);
  infinity = gsec_equal(zb, zero, 48) == GSEC_OK;
  fe_p384_inv(&inv, &p->z);
  fe_p384_mul(x_out, &p->x, &inv);
  fe_p384_mul(y_out, &p->y, &inv);
  gsec_wipe(&inv, sizeof inv);
  gsec_wipe(zb, sizeof zb);
  if (infinity) {
    gsec_wipe(x_out, sizeof *x_out);
    gsec_wipe(y_out, sizeof *y_out);
    return 0;
  }
  return 1;
}

void p384_point_base(p384_point * p) {
  p->x = BASE_X;
  p->y = BASE_Y;
  fe_p384_set_u32(&p->z, 1);
}

void p384_point_add(p384_point * o, const p384_point * a, const p384_point * b) {
  point_add(o, a, b);
}

int p384_point_affine(fe_p384 * x_out, fe_p384 * y_out, const p384_point * p) {
  return affine(x_out, y_out, p);
}

void p384_scalarmult_proj(p384_point * out, const unsigned char scalar[48],
    const p384_point * base) {
  p384_point r;
  p384_point q;
  p384_point sum;
  int i;

  point_set_identity(&r);
  q = *base;
  for (i = 0; i < 384; i++) {
    int bit = (scalar[47 - (i >> 3)] >> (i & 7)) & 1;

    point_add(&sum, &r, &q);
    point_cmov(&r, &sum, bit);
    point_add(&q, &q, &q);
  }
  *out = r;
  gsec_wipe(&r, sizeof r);
  gsec_wipe(&q, sizeof q);
  gsec_wipe(&sum, sizeof sum);
}

int p384_scalarmult(fe_p384 * x_out, fe_p384 * y_out,
    const unsigned char scalar[48], const p384_point * base) {
  p384_point r;
  int ok;

  p384_scalarmult_proj(&r, scalar, base);
  ok = affine(x_out, y_out, &r);
  gsec_wipe(&r, sizeof r);
  return ok;
}

int p384_scalarmult_base(fe_p384 * x_out, fe_p384 * y_out,
    const unsigned char scalar[48]) {
  p384_point base;

  p384_point_base(&base);
  return p384_scalarmult(x_out, y_out, scalar, &base);
}
