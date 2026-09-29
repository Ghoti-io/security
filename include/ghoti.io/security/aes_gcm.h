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
 * @file aes_gcm.h
 *
 * AES-GCM, as NIST SP 800-38D specifies it, at 128, 192, and 256 bits.
 *
 * Nonce reuse under one key destroys authentication. The nonce is the
 * caller's. A 12-byte nonce is the one the standard prefers. Any other
 * positive length is hashed into the initial counter. An empty nonce is
 * rejected.
 *
 * Both operations are one shot. Decrypt checks the tag before it returns,
 * and a mismatch wipes the plaintext it produced. There is no call that
 * hands back plaintext and a tag to check later.
 *
 * GHASH multiplies in GF(2^128) with the field polynomial the standard
 * names. A key byte, a block byte, and a hash-subkey bit are not a branch
 * condition and not a table index.
 */

#ifndef GHOTI_IO_GSEC_AES_GCM_H
#define GHOTI_IO_GSEC_AES_GCM_H

#include <ghoti.io/security/aes.h>
#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Encrypt and write the tag.
 *
 * Nonce reuse under one key destroys authentication.
 *
 * @param key Key bytes.
 * @param key_len 16, 24, or 32.
 * @param iv Nonce. NULL, or a length of 0, is ::GSEC_ERR_INVALID.
 * @param iv_len Nonce length in bytes. 12 is the length SP 800-38D prefers.
 * @param aad Additional data. NULL with a length of 0 is empty.
 * @param aad_len Additional-data length. A bit length that does not fit in
 *   64 bits is ::GSEC_ERR_LIMIT.
 * @param pt Plaintext. NULL with a length of 0 is empty.
 * @param pt_len Plaintext length. Above 2^36 − 32 bytes is ::GSEC_ERR_LIMIT.
 * @param ct Ciphertext, @p pt_len bytes. May be @p pt. A partial overlap is
 *   ::GSEC_ERR_INVALID. NULL when @p pt_len is 0.
 * @param tag Tag output. NULL is ::GSEC_ERR_INVALID. Must not overlap
 *   @p pt or @p ct.
 * @param tag_len 12 through 16. A shorter tag is
 *   ::GSEC_ERR_INVALID: SP 800-38D allows 4 and 8 only where the
 *   caller bounds the number of forgery attempts, which this
 *   library cannot do on its behalf.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, or ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_aes_gcm_encrypt(const void * key, size_t key_len,
    const void * iv, size_t iv_len, const void * aad, size_t aad_len,
    const void * pt, size_t pt_len, void * ct, void * tag, size_t tag_len);

/**
 * @brief Decrypt and check the tag.
 *
 * Nonce reuse under one key destroys authentication. On
 * ::GSEC_ERR_MISMATCH the plaintext buffer is wiped. The ciphertext is
 * left as the caller passed it when it is a different buffer.
 *
 * @param key Key bytes.
 * @param key_len 16, 24, or 32.
 * @param iv Nonce. NULL, or a length of 0, is ::GSEC_ERR_INVALID.
 * @param iv_len Nonce length in bytes.
 * @param aad Additional data. NULL with a length of 0 is empty.
 * @param aad_len Additional-data length.
 * @param ct Ciphertext. NULL with a length of 0 is empty.
 * @param ct_len Ciphertext length. Above 2^36 − 32 bytes is ::GSEC_ERR_LIMIT.
 * @param pt Plaintext output, @p ct_len bytes. May be @p ct. A partial
 *   overlap is ::GSEC_ERR_INVALID. NULL when @p ct_len is 0.
 * @param tag Tag to check. Copied before any plaintext is written, so it
 *   may overlap @p pt.
 * @param tag_len 12 through 16, and the length that was
 *   produced. A shorter tag is a different authenticator.
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH, ::GSEC_ERR_INVALID, or
 *   ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_aes_gcm_decrypt(const void * key, size_t key_len,
    const void * iv, size_t iv_len, const void * aad, size_t aad_len,
    const void * ct, size_t ct_len, void * pt, const void * tag,
    size_t tag_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_AES_GCM_H */
