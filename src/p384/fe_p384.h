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
 * Field elements modulo the P-384 prime. Twelve little-endian 32-bit
 * limbs. A limb is not a branch condition and not a table index.
 */

#ifndef GHOTI_IO_GSEC_FE_P384_H
#define GHOTI_IO_GSEC_FE_P384_H

#include <ghoti.io/security/macros.h>

#include <stdint.h>

typedef struct {
  uint32_t v[12];
} fe_p384;

void fe_p384_add(fe_p384 * o, const fe_p384 * a, const fe_p384 * b);
void fe_p384_sub(fe_p384 * o, const fe_p384 * a, const fe_p384 * b);
void fe_p384_mul(fe_p384 * o, const fe_p384 * a, const fe_p384 * b);
void fe_p384_cmov(fe_p384 * o, const fe_p384 * a, int bit);
void fe_p384_inv(fe_p384 * o, const fe_p384 * z);
int fe_p384_from_bytes(fe_p384 * o, const unsigned char s[48]);
void fe_p384_to_bytes(unsigned char out[48], const fe_p384 * n);
void fe_p384_set_u32(fe_p384 * o, uint32_t x);

extern const fe_p384 FE_P384_A;
extern const fe_p384 FE_P384_B;
extern const fe_p384 FE_P384_B3;

#endif /* GHOTI_IO_GSEC_FE_P384_H */
