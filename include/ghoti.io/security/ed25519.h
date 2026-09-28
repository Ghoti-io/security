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
 * @file ed25519.h
 *
 * Ed25519, as RFC 8032 specifies it.
 *
 * The seed and the public key are 32 bytes. The signature is 64. Signing
 * is deterministic: the same seed and message produce the same signature.
 * Verification rejects a non-canonical point and a scalar S that is not
 * strictly less than the group order. ::gsec_ed25519_sign is pure Ed25519.
 * ::gsec_ed25519_ctx_sign binds a context. ::gsec_ed25519_ph_sign signs
 * SHA-512 of the message, with a context that may be empty.
 */

#ifndef GHOTI_IO_GSEC_ED25519_H
#define GHOTI_IO_GSEC_ED25519_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Seed and public-key length. */
#define GSEC_ED25519_LEN 32u

/** Signature length. */
#define GSEC_ED25519_SIG_LEN 64u

/**
 * @brief Derive the public key from a seed.
 *
 * @param seed Exactly ::GSEC_ED25519_LEN bytes.
 * @param out Exactly ::GSEC_ED25519_LEN bytes. May alias @p seed.
 * @return ::GSEC_OK or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_ed25519_public(const void * seed, void * out);

/**
 * @brief Sign a message.
 *
 * @param seed Exactly ::GSEC_ED25519_LEN bytes.
 * @param data Message. NULL with @p n of 0 signs the empty message. NULL
 *   with @p n greater than 0 is ::GSEC_ERR_INVALID.
 * @param n Message length in bytes. The length is public.
 * @param out Exactly ::GSEC_ED25519_SIG_LEN bytes. May alias @p seed.
 * @return ::GSEC_OK or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_ed25519_sign(const void * seed, const void * data,
    size_t n, void * out);

/**
 * @brief Verify a signature.
 *
 * @param public_key Exactly ::GSEC_ED25519_LEN bytes.
 * @param data Message. NULL with @p n of 0 is the empty message.
 * @param n Message length in bytes.
 * @param sig Exactly ::GSEC_ED25519_SIG_LEN bytes.
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH when the signature, the point, or
 *   S is not accepted, or ::GSEC_ERR_INVALID for a null argument.
 */
GSEC_API GSEC_Result gsec_ed25519_verify(const void * public_key,
    const void * data, size_t n, const void * sig);

/**
 * @brief Sign a message with an Ed25519 context.
 *
 * @param ctx Context, at most 255 bytes. Empty is accepted. NULL with
 *   @p ctx_len of 0 is the empty context.
 * @return ::GSEC_OK or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_ed25519_ctx_sign(const void * seed,
    const void * data, size_t n, const void * ctx, size_t ctx_len, void * out);

/**
 * @brief Verify an Ed25519ctx signature.
 */
GSEC_API GSEC_Result gsec_ed25519_ctx_verify(const void * public_key,
    const void * data, size_t n, const void * sig, const void * ctx,
    size_t ctx_len);

/**
 * @brief Sign SHA-512 of a message, with a context.
 *
 * The context may be empty. The prehash is SHA-512.
 */
GSEC_API GSEC_Result gsec_ed25519_ph_sign(const void * seed,
    const void * data, size_t n, const void * ctx, size_t ctx_len, void * out);

/**
 * @brief Verify an Ed25519ph signature.
 */
GSEC_API GSEC_Result gsec_ed25519_ph_verify(const void * public_key,
    const void * data, size_t n, const void * sig, const void * ctx,
    size_t ctx_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_ED25519_H */
