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
 * P-256 points in projective coordinates. Addition is the complete formula,
 * so the identity and doubling need no special case. A secret scalar
 * selects the sum with a mask.
 */

#ifndef GHOTI_IO_GSEC_P256_POINT_H
#define GHOTI_IO_GSEC_P256_POINT_H

#include <ghoti.io/security/macros.h>

#include "fe_p256.h"

typedef struct {
  fe_p256 x;
  fe_p256 y;
  fe_p256 z;
} p256_point;

int p256_point_decode(p256_point * p, const unsigned char xy[64]);
void p256_point_base(p256_point * p);
void p256_point_add(p256_point * o, const p256_point * a, const p256_point * b);
void p256_scalarmult_proj(p256_point * out, const unsigned char scalar[32],
    const p256_point * base);
int p256_point_affine(fe_p256 * x_out, fe_p256 * y_out, const p256_point * p);
int p256_scalarmult(fe_p256 * x_out, fe_p256 * y_out,
    const unsigned char scalar[32], const p256_point * base);
int p256_scalarmult_base(fe_p256 * x_out, fe_p256 * y_out,
    const unsigned char scalar[32]);

#endif /* GHOTI_IO_GSEC_P256_POINT_H */
