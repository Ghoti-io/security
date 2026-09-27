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
 * @file ecdsa_p256.h
 *
 * ECDSA on NIST P-256, with SHA-256 and RFC 6979.
 *
 * The private key, each coordinate, and each half of a signature are 32
 * bytes, big-endian. The public key is x then y, 64 bytes, with no
 * uncompressed-point prefix. The signature is r then s, 64 bytes.
 * Signing hashes the message with SHA-256 and derives the nonce from the
 * private key and that hash, so the same key and message sign the same
 * way. The signature it emits has the low s. Verification accepts a high
 * s. An r or s of zero, or one that is not strictly less than the group
 * order, does not verify.
 */

#ifndef GHOTI_IO_GSEC_ECDSA_P256_H
#define GHOTI_IO_GSEC_ECDSA_P256_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Private-key and coordinate length. */
#define GSEC_ECDSA_P256_LEN 32u

/** Public key length: x coordinate, then y coordinate. */
#define GSEC_ECDSA_P256_PUBLIC_LEN 64u

/** Signature length: r, then s. */
#define GSEC_ECDSA_P256_SIG_LEN 64u

/**
 * @brief Multiply the private key by the base point and write the public key.
 *
 * @param scalar Exactly ::GSEC_ECDSA_P256_LEN bytes. It must be in the
 *   range 1 to n - 1, where n is the group order.
 * @param out Exactly ::GSEC_ECDSA_P256_PUBLIC_LEN bytes. May alias
 *   @p scalar. Wiped when the key is not in range.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_ecdsa_p256_public(const void * scalar, void * out);

/**
 * @brief Sign a message.
 *
 * The nonce is RFC 6979. s is replaced with n - s when it is larger than
 * n / 2.
 *
 * @param scalar Exactly ::GSEC_ECDSA_P256_LEN bytes, in the range 1 to
 *   n - 1.
 * @param msg Message. NULL only when @p msg_len is 0.
 * @param msg_len Message length in bytes.
 * @param sig Exactly ::GSEC_ECDSA_P256_SIG_LEN bytes. May alias @p scalar
 *   or @p msg. Wiped when the key is not in range.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, ::GSEC_ERR_LIMIT, or
 *   ::GSEC_ERR_INTERNAL.
 */
GSEC_API GSEC_Result gsec_ecdsa_p256_sign(const void * scalar, const void * msg,
    size_t msg_len, void * sig);

/**
 * @brief Verify a signature.
 *
 * A high s is accepted. A bad point, a non-canonical coordinate, an r or
 * s that is zero or not strictly less than the group order, and a
 * signature that does not satisfy the equation are ::GSEC_ERR_MISMATCH.
 *
 * @param pub Exactly ::GSEC_ECDSA_P256_PUBLIC_LEN bytes, x then y.
 * @param msg Message. NULL only when @p msg_len is 0.
 * @param msg_len Message length in bytes.
 * @param sig Exactly ::GSEC_ECDSA_P256_SIG_LEN bytes, r then s.
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH, ::GSEC_ERR_INVALID, or
 *   ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_ecdsa_p256_verify(const void * pub, const void * msg,
    size_t msg_len, const void * sig);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_ECDSA_P256_H */
