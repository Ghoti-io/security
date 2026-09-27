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
 * Field elements modulo 2^255−19. Sixteen radix-2^16 limbs. X25519 and
 * Ed25519 both use this. A limb is not a branch condition and not a
 * table index.
 */

#ifndef GHOTI_IO_GSEC_FE25519_H
#define GHOTI_IO_GSEC_FE25519_H

#include <ghoti.io/security/macros.h>

#include <stdint.h>

typedef int64_t fe25519[16];

void fe25519_add(fe25519 o, const fe25519 a, const fe25519 b);
void fe25519_sub(fe25519 o, const fe25519 a, const fe25519 b);
void fe25519_mul(fe25519 o, const fe25519 a, const fe25519 b);
void fe25519_sq(fe25519 o, const fe25519 a);
void fe25519_cswap(fe25519 p, fe25519 q, int bit);
void fe25519_cmov(fe25519 o, const fe25519 a, int bit);
void fe25519_invert(fe25519 o, const fe25519 z);
void fe25519_from_bytes(fe25519 o, const unsigned char s[32]);
void fe25519_to_bytes(unsigned char out[32], const fe25519 n);

#endif /* GHOTI_IO_GSEC_FE25519_H */
