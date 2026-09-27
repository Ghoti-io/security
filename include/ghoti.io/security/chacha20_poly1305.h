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
 * @file chacha20_poly1305.h
 *
 * AEAD_CHACHA20_POLY1305, as RFC 8439 specifies it.
 *
 * The caller is TLS 1.3, whose cipher suite is this construction. The
 * key is 32 bytes. The nonce is 12 bytes. The tag is 16 bytes.
 *
 * Nonce reuse under one key destroys authentication. The nonce is the
 * caller's. A protocol that has a nonce of a different length has to
 * define how that nonce becomes these 12 bytes. This function does not
 * guess.
 *
 * Both operations are one shot. Decrypt checks the tag before it returns,
 * and a mismatch wipes the plaintext it produced. There is no call that
 * hands back plaintext and a tag to check later.
 */

#ifndef GHOTI_IO_GSEC_CHACHA20_POLY1305_H
#define GHOTI_IO_GSEC_CHACHA20_POLY1305_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** RFC 8439 key length. */
#define GSEC_CHACHA20_KEY_LEN 32u

/** RFC 8439 nonce length. The caller supplies exactly this many bytes. */
#define GSEC_CHACHA20_NONCE_LEN 12u

/** Poly1305 tag length. */
#define GSEC_POLY1305_TAG_LEN 16u

/**
 * @brief Encrypt and write the tag.
 *
 * Nonce reuse under one key destroys authentication.
 *
 * @param key Exactly ::GSEC_CHACHA20_KEY_LEN bytes.
 * @param nonce Exactly ::GSEC_CHACHA20_NONCE_LEN bytes.
 * @param aad Additional data. NULL with a length of 0 is empty.
 * @param aad_len Additional-data length.
 * @param pt Plaintext. NULL with a length of 0 is empty.
 * @param pt_len Plaintext length. Above (2^32 − 1) × 64 bytes is
 *   ::GSEC_ERR_LIMIT, because the block counter is 32 bits and the first
 *   block is the Poly1305 key.
 * @param ct Ciphertext, @p pt_len bytes. May be @p pt. A partial overlap is
 *   ::GSEC_ERR_INVALID. NULL when @p pt_len is 0.
 * @param tag Exactly ::GSEC_POLY1305_TAG_LEN bytes. Must not overlap
 *   @p pt or @p ct.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, or ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_chacha20_poly1305_encrypt(const void * key,
    const void * nonce, const void * aad, size_t aad_len, const void * pt,
    size_t pt_len, void * ct, void * tag);

/**
 * @brief Decrypt and check the tag.
 *
 * Nonce reuse under one key destroys authentication. On
 * ::GSEC_ERR_MISMATCH the plaintext buffer is wiped. The ciphertext is
 * left as the caller passed it when it is a different buffer.
 *
 * @param key Exactly ::GSEC_CHACHA20_KEY_LEN bytes.
 * @param nonce Exactly ::GSEC_CHACHA20_NONCE_LEN bytes.
 * @param aad Additional data. NULL with a length of 0 is empty.
 * @param aad_len Additional-data length.
 * @param ct Ciphertext. NULL with a length of 0 is empty.
 * @param ct_len Ciphertext length. Above (2^32 − 1) × 64 bytes is
 *   ::GSEC_ERR_LIMIT.
 * @param pt Plaintext output, @p ct_len bytes. May be @p ct. A partial
 *   overlap is ::GSEC_ERR_INVALID. NULL when @p ct_len is 0.
 * @param tag Exactly ::GSEC_POLY1305_TAG_LEN bytes. Copied before any
 *   plaintext is written, so it may overlap @p pt.
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH, ::GSEC_ERR_INVALID, or
 *   ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_chacha20_poly1305_decrypt(const void * key,
    const void * nonce, const void * aad, size_t aad_len, const void * ct,
    size_t ct_len, void * pt, const void * tag);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_CHACHA20_POLY1305_H */
