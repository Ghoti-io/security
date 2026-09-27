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
 * Shared RSA padding. Verification and signing both call this, so the
 * DigestInfo prefixes and the PSS bit length cannot drift apart.
 */

#ifndef GHOTI_IO_GSEC_RSA_PAD_H
#define GHOTI_IO_GSEC_RSA_PAD_H

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/rsa.h>
#include <ghoti.io/security/sha512.h>

#include "bn.h"

#include <stddef.h>
#include <stdint.h>

GSEC_Result rsa_hash_one(uint32_t id, const void * data, size_t n,
    unsigned char out[GSEC_SHA512_DIGEST_LEN], size_t * hlen,
    const unsigned char ** prefix, size_t * prefix_len);

GSEC_Result rsa_load_public(bn * mod, const unsigned char ** exp,
    size_t * exp_len, const void * n, size_t n_len, const void * e,
    size_t e_len, size_t * k);

GSEC_Result rsa_mgf1(uint32_t hash, const unsigned char * seed, size_t seed_len,
    unsigned char * mask, size_t mask_len);

/* RFC 8017: emBits is the modulus bit length minus one. */
void rsa_em_shape(const unsigned char * np, size_t k, size_t * em_len,
    unsigned * unused);

/* Private exponent, checked against the modulus. The caller wipes d. */
GSEC_Result rsa_load_private(bn * d, const bn * mod, const void * raw,
    size_t raw_len);

/* em^d mod n, blinded. sig is wiped when the result is not GSEC_OK. */
GSEC_Result rsa_blinded(unsigned char * sig, size_t k, const bn * mod,
    const unsigned char * e, size_t e_len, const bn * d,
    const unsigned char * em);

#endif /* GHOTI_IO_GSEC_RSA_PAD_H */
