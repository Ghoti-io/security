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
 * P-384 points in projective coordinates. Addition is the complete formula,
 * so the identity and doubling need no special case. A secret scalar
 * selects the sum with a mask.
 */

#ifndef GHOTI_IO_GSEC_P384_POINT_H
#define GHOTI_IO_GSEC_P384_POINT_H

#include <ghoti.io/security/macros.h>

#include "fe_p384.h"

typedef struct {
  fe_p384 x;
  fe_p384 y;
  fe_p384 z;
} p384_point;

int p384_point_decode(p384_point * p, const unsigned char xy[96]);
void p384_point_base(p384_point * p);
void p384_point_add(p384_point * o, const p384_point * a, const p384_point * b);
void p384_scalarmult_proj(p384_point * out, const unsigned char scalar[48],
    const p384_point * base);
int p384_point_affine(fe_p384 * x_out, fe_p384 * y_out, const p384_point * p);
int p384_scalarmult(fe_p384 * x_out, fe_p384 * y_out,
    const unsigned char scalar[48], const p384_point * base);
int p384_scalarmult_base(fe_p384 * x_out, fe_p384 * y_out,
    const unsigned char scalar[48]);

#endif /* GHOTI_IO_GSEC_P384_POINT_H */
