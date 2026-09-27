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
 * Integers modulo the P-256 group order. Eight little-endian 32-bit limbs.
 * A limb is not a branch condition and not a table index.
 */

#ifndef GHOTI_IO_GSEC_SC_P256_H
#define GHOTI_IO_GSEC_SC_P256_H

#include <ghoti.io/security/macros.h>

#include <stdint.h>

typedef struct {
  uint32_t v[8];
} sc_p256;

void sc_p256_set_bytes(sc_p256 * o, const unsigned char s[32]);
void sc_p256_to_bytes(unsigned char out[32], const sc_p256 * n);
uint32_t sc_p256_lt_n(const sc_p256 * a);
void sc_p256_reduce_bytes(sc_p256 * o, const unsigned char s[32]);
void sc_p256_add(sc_p256 * o, const sc_p256 * a, const sc_p256 * b);
void sc_p256_sub(sc_p256 * o, const sc_p256 * a, const sc_p256 * b);
void sc_p256_mul(sc_p256 * o, const sc_p256 * a, const sc_p256 * b);
void sc_p256_cmov(sc_p256 * o, const sc_p256 * a, uint32_t bit);
void sc_p256_inv(sc_p256 * o, const sc_p256 * z);
uint32_t sc_p256_gt_half(const sc_p256 * a);

#endif /* GHOTI_IO_GSEC_SC_P256_H */
