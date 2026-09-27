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
 * @file des.h
 *
 * DES and three-key Triple DES, as FIPS 46-3 specifies them, plus CBC.
 *
 * Both ciphers are broken. They are here because old formats still name
 * them. Do not use either for a new design. The substitution boxes are
 * indexed by bits that depend on the key, so this is not a constant-time
 * implementation and it is not in the constant-time gate.
 *
 * The low bit of each key byte is the parity bit DES defines and is not
 * a key bit. A wrong parity is accepted: the other 56 bits are the key.
 * Triple DES is encrypt, decrypt, encrypt with three 8-byte keys.
 *
 * CBC does not authenticate. The initialization vector is the caller's.
 * Repeating it under one key leaks the equality of plaintext prefixes.
 * The length is a multiple of the block. Padding is the caller's.
 */

#ifndef GHOTI_IO_GSEC_DES_H
#define GHOTI_IO_GSEC_DES_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** DES block length in bytes. */
#define GSEC_DES_BLOCK_LEN 8u

/** DES key length in bytes, including the parity bit in each byte. */
#define GSEC_DES_KEY_LEN 8u

/** Three-key Triple DES key length: three DES keys, in order. */
#define GSEC_DES_EDE3_KEY_LEN 24u

/**
 * @brief Encrypt one DES block.
 *
 * @param key Exactly ::GSEC_DES_KEY_LEN bytes.
 * @param in Exactly ::GSEC_DES_BLOCK_LEN bytes.
 * @param out Exactly ::GSEC_DES_BLOCK_LEN bytes. May be @p in.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_des_encrypt(const void * key, const void * in,
    void * out);

/**
 * @brief Decrypt one DES block.
 *
 * @param key Exactly ::GSEC_DES_KEY_LEN bytes.
 * @param in Exactly ::GSEC_DES_BLOCK_LEN bytes.
 * @param out Exactly ::GSEC_DES_BLOCK_LEN bytes. May be @p in.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_des_decrypt(const void * key, const void * in,
    void * out);

/**
 * @brief Encrypt one block with three-key Triple DES.
 *
 * @param key Exactly ::GSEC_DES_EDE3_KEY_LEN bytes: K1, K2, K3.
 * @param in Exactly ::GSEC_DES_BLOCK_LEN bytes.
 * @param out Exactly ::GSEC_DES_BLOCK_LEN bytes. May be @p in.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_des_ede3_encrypt(const void * key, const void * in,
    void * out);

/**
 * @brief Decrypt one block with three-key Triple DES.
 *
 * @param key Exactly ::GSEC_DES_EDE3_KEY_LEN bytes: K1, K2, K3.
 * @param in Exactly ::GSEC_DES_BLOCK_LEN bytes.
 * @param out Exactly ::GSEC_DES_BLOCK_LEN bytes. May be @p in.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_des_ede3_decrypt(const void * key, const void * in,
    void * out);

/**
 * @brief Encrypt with DES-CBC. The length is a multiple of the block.
 *
 * @param key Exactly ::GSEC_DES_KEY_LEN bytes.
 * @param iv Exactly ::GSEC_DES_BLOCK_LEN bytes. The caller's nonce.
 * @param in Plaintext. NULL only when @p len is 0.
 * @param len Zero, or a multiple of ::GSEC_DES_BLOCK_LEN.
 * @param out Ciphertext, @p len bytes. May be @p in. A partial overlap is
 *   ::GSEC_ERR_INVALID.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_des_cbc_encrypt(const void * key, const void * iv,
    const void * in, size_t len, void * out);

/**
 * @brief Decrypt with DES-CBC. The length is a multiple of the block.
 *
 * @param key Exactly ::GSEC_DES_KEY_LEN bytes.
 * @param iv Exactly ::GSEC_DES_BLOCK_LEN bytes.
 * @param in Ciphertext. NULL only when @p len is 0.
 * @param len Zero, or a multiple of ::GSEC_DES_BLOCK_LEN.
 * @param out Plaintext, @p len bytes. May be @p in.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_des_cbc_decrypt(const void * key, const void * iv,
    const void * in, size_t len, void * out);

/**
 * @brief Encrypt with three-key Triple DES in CBC mode.
 *
 * @param key Exactly ::GSEC_DES_EDE3_KEY_LEN bytes.
 * @param iv Exactly ::GSEC_DES_BLOCK_LEN bytes. The caller's nonce.
 * @param in Plaintext. NULL only when @p len is 0.
 * @param len Zero, or a multiple of ::GSEC_DES_BLOCK_LEN.
 * @param out Ciphertext, @p len bytes. May be @p in.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_des_ede3_cbc_encrypt(const void * key,
    const void * iv, const void * in, size_t len, void * out);

/**
 * @brief Decrypt with three-key Triple DES in CBC mode.
 *
 * @param key Exactly ::GSEC_DES_EDE3_KEY_LEN bytes.
 * @param iv Exactly ::GSEC_DES_BLOCK_LEN bytes.
 * @param in Ciphertext. NULL only when @p len is 0.
 * @param len Zero, or a multiple of ::GSEC_DES_BLOCK_LEN.
 * @param out Plaintext, @p len bytes. May be @p in.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_des_ede3_cbc_decrypt(const void * key,
    const void * iv, const void * in, size_t len, void * out);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_DES_H */
