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
 * Integers modulo the P-384 group order. Twelve little-endian 32-bit
 * limbs. A limb is not a branch condition and not a table index.
 */

#ifndef GHOTI_IO_GSEC_SC_P384_H
#define GHOTI_IO_GSEC_SC_P384_H

#include <ghoti.io/security/macros.h>

#include <stdint.h>

typedef struct {
  uint32_t v[12];
} sc_p384;

void sc_p384_set_bytes(sc_p384 * o, const unsigned char s[48]);
void sc_p384_to_bytes(unsigned char out[48], const sc_p384 * n);
uint32_t sc_p384_lt_n(const sc_p384 * a);
void sc_p384_reduce_bytes(sc_p384 * o, const unsigned char s[48]);
void sc_p384_add(sc_p384 * o, const sc_p384 * a, const sc_p384 * b);
void sc_p384_sub(sc_p384 * o, const sc_p384 * a, const sc_p384 * b);
void sc_p384_mul(sc_p384 * o, const sc_p384 * a, const sc_p384 * b);
void sc_p384_cmov(sc_p384 * o, const sc_p384 * a, uint32_t bit);
void sc_p384_inv(sc_p384 * o, const sc_p384 * z);
uint32_t sc_p384_gt_half(const sc_p384 * a);

#endif /* GHOTI_IO_GSEC_SC_P384_H */
