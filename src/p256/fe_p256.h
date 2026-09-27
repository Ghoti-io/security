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
 * Field elements modulo the P-256 prime. Eight little-endian 32-bit limbs.
 * A limb is not a branch condition and not a table index.
 */

#ifndef GHOTI_IO_GSEC_FE_P256_H
#define GHOTI_IO_GSEC_FE_P256_H

#include <ghoti.io/security/macros.h>

#include <stdint.h>

typedef struct {
  uint32_t v[8];
} fe_p256;

void fe_p256_add(fe_p256 * o, const fe_p256 * a, const fe_p256 * b);
void fe_p256_sub(fe_p256 * o, const fe_p256 * a, const fe_p256 * b);
void fe_p256_mul(fe_p256 * o, const fe_p256 * a, const fe_p256 * b);
void fe_p256_cmov(fe_p256 * o, const fe_p256 * a, int bit);
void fe_p256_inv(fe_p256 * o, const fe_p256 * z);
int fe_p256_from_bytes(fe_p256 * o, const unsigned char s[32]);
void fe_p256_to_bytes(unsigned char out[32], const fe_p256 * n);
void fe_p256_set_u32(fe_p256 * o, uint32_t x);

extern const fe_p256 FE_P256_A;
extern const fe_p256 FE_P256_B;
extern const fe_p256 FE_P256_B3;

#endif /* GHOTI_IO_GSEC_FE_P256_H */
