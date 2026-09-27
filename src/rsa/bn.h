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
 * Fixed-capacity integers for RSA. bn_modexp walks a public exponent and
 * branches on its bits. bn_modexp_ct, bn_modinv_ct, bn_modmul, and
 * bn_reduce_ct do not: a private exponent and a blinding factor go
 * through those. The modulus is odd and at most 4096 bits.
 */

#ifndef GHOTI_IO_GSEC_RSA_BN_H
#define GHOTI_IO_GSEC_RSA_BN_H

#include <ghoti.io/security/macros.h>

#include <stddef.h>
#include <stdint.h>

#define BN_LIMBS 128

typedef struct {
  uint32_t v[BN_LIMBS];
  int n;
} bn;

int bn_limbs_for(size_t nbytes);
int bn_from_be(bn * o, const unsigned char * p, size_t n);
void bn_to_be(unsigned char * out, size_t n, const bn * a);
int bn_cmp(const bn * a, const bn * b);
int bn_modexp(bn * out, const bn * base, const unsigned char * exp, size_t exp_len,
    const bn * mod);
int bn_modexp_ct(bn * out, const bn * base, const bn * exp, const bn * mod);
int bn_modinv_ct(bn * out, const bn * a, const bn * mod);
int bn_modmul(bn * out, const bn * a, const bn * b, const bn * mod);
void bn_reduce_ct(bn * r, const bn * mod);

/* 1 when a is strictly below mod. Both are the modulus width. No branch. */
uint32_t bn_below(const bn * a, const bn * mod);

/* 1 when any limb is nonzero. No branch. */
uint32_t bn_nonzero(const bn * a);

#endif /* GHOTI_IO_GSEC_RSA_BN_H */
