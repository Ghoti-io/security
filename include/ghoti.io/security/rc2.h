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
 * @file rc2.h
 *
 * RC2, as RFC 2268 specifies it, plus CBC.
 *
 * The cipher is broken. It is here because PKCS#12 and PBES1 still name
 * it. Do not use it for a new design. A new cipher is AES-GCM or
 * ChaCha20-Poly1305. The key expansion indexes a
 * substitution table with key bytes, so this is not constant-time and
 * it is not in the constant-time gate.
 *
 * The key is 1 to 128 bytes. The effective length is 1 to 1024 bits, and
 * it is not the same thing as the key length: a 40-bit effective key is
 * five key bytes with the effective length set to 40. CBC does not
 * authenticate. The initialization vector is the caller's. Padding is
 * the caller's.
 */

#ifndef GHOTI_IO_GSEC_RC2_H
#define GHOTI_IO_GSEC_RC2_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** RC2 block length in bytes. */
#define GSEC_RC2_BLOCK_LEN 8u

/** Shortest key, in bytes. */
#define GSEC_RC2_KEY_MIN 1u

/** Longest key, in bytes. */
#define GSEC_RC2_KEY_MAX 128u

/** Shortest effective key length, in bits. */
#define GSEC_RC2_EFFECTIVE_MIN 1u

/** Longest effective key length, in bits. */
#define GSEC_RC2_EFFECTIVE_MAX 1024u

/**
 * @brief Encrypt one RC2 block.
 *
 * @param key Key bytes.
 * @param key_len 1 to 128.
 * @param effective_bits Effective key length, 1 to 1024.
 * @param in Exactly ::GSEC_RC2_BLOCK_LEN bytes.
 * @param out Exactly ::GSEC_RC2_BLOCK_LEN bytes. May be @p in.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_rc2_encrypt(const void * key, size_t key_len,
    uint32_t effective_bits, const void * in, void * out);

/**
 * @brief Decrypt one RC2 block.
 *
 * @param key Key bytes.
 * @param key_len 1 to 128.
 * @param effective_bits The effective length used to encrypt.
 * @param in Exactly ::GSEC_RC2_BLOCK_LEN bytes.
 * @param out Exactly ::GSEC_RC2_BLOCK_LEN bytes. May be @p in.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_rc2_decrypt(const void * key, size_t key_len,
    uint32_t effective_bits, const void * in, void * out);

/**
 * @brief Encrypt with RC2-CBC. The length is a multiple of the block.
 *
 * @param key Key bytes.
 * @param key_len 1 to 128.
 * @param effective_bits Effective key length, 1 to 1024.
 * @param iv Exactly ::GSEC_RC2_BLOCK_LEN bytes. The caller's nonce.
 * @param in Plaintext. NULL only when @p len is 0.
 * @param len Zero, or a multiple of ::GSEC_RC2_BLOCK_LEN.
 * @param out Ciphertext, @p len bytes. May be @p in.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_rc2_cbc_encrypt(const void * key, size_t key_len,
    uint32_t effective_bits, const void * iv, const void * in, size_t len,
    void * out);

/**
 * @brief Decrypt with RC2-CBC.
 *
 * @param key Key bytes.
 * @param key_len 1 to 128.
 * @param effective_bits The effective length used to encrypt.
 * @param iv Exactly ::GSEC_RC2_BLOCK_LEN bytes.
 * @param in Ciphertext. NULL only when @p len is 0.
 * @param len Zero, or a multiple of ::GSEC_RC2_BLOCK_LEN.
 * @param out Plaintext, @p len bytes. May be @p in.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_rc2_cbc_decrypt(const void * key, size_t key_len,
    uint32_t effective_bits, const void * iv, const void * in, size_t len,
    void * out);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_RC2_H */
