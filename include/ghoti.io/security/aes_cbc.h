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
 * @file aes_cbc.h
 *
 * AES in CBC mode, as NIST SP 800-38A specifies the mode, at 128, 192,
 * and 256 bits.
 *
 * The initialization vector is 16 bytes and is the caller's. Repeating it
 * under one key leaks the equality of plaintext prefixes. This mode does
 * not authenticate. A caller that needs authentication uses AES-GCM.
 *
 * The length is a multiple of the block. Padding is the caller's: 7z
 * already knows the compressed length and applies its own alignment.
 * A length of zero is success and does not read the buffers. The schedule
 * is wiped before return.
 */

#ifndef GHOTI_IO_GSEC_AES_CBC_H
#define GHOTI_IO_GSEC_AES_CBC_H

#include <ghoti.io/security/aes.h>
#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Encrypt with CBC. The length is a multiple of the block.
 *
 * @param key Key bytes.
 * @param key_len 16, 24, or 32.
 * @param iv Exactly ::GSEC_AES_BLOCK_LEN bytes. The caller's nonce.
 * @param in Plaintext. NULL only when @p len is 0.
 * @param len Plaintext length. Zero, or a multiple of ::GSEC_AES_BLOCK_LEN.
 *   Any other length is ::GSEC_ERR_INVALID.
 * @param out Ciphertext, @p len bytes. May be @p in. A partial overlap is
 *   ::GSEC_ERR_INVALID.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_aes_cbc_encrypt(const void * key, size_t key_len,
    const void * iv, const void * in, size_t len, void * out);

/**
 * @brief Decrypt with CBC. The length is a multiple of the block.
 *
 * @param key Key bytes.
 * @param key_len 16, 24, or 32.
 * @param iv Exactly ::GSEC_AES_BLOCK_LEN bytes. The same nonce encryption used.
 * @param in Ciphertext. NULL only when @p len is 0.
 * @param len Ciphertext length. Zero, or a multiple of ::GSEC_AES_BLOCK_LEN.
 * @param out Plaintext, @p len bytes. May be @p in. A partial overlap is
 *   ::GSEC_ERR_INVALID.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_aes_cbc_decrypt(const void * key, size_t key_len,
    const void * iv, const void * in, size_t len, void * out);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_AES_CBC_H */
