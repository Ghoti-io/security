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
 * @file aes.h
 *
 * AES, as FIPS 197 specifies it, at 128, 192, and 256 bits.
 *
 * The substitution is the field inverse and the affine map. A key byte
 * and a block byte are not a branch condition and not a table index.
 * The round number is public, because it follows the key length.
 *
 * ::gsec_aes_encrypt_init expands the key for both directions.
 * ::gsec_aes_encrypt_wipe destroys that schedule. The one-shot functions
 * expand, run one block, and wipe before returning. There is no function
 * that prints a key or a block.
 */

#ifndef GHOTI_IO_GSEC_AES_H
#define GHOTI_IO_GSEC_AES_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Block length in bytes. Encrypt and decrypt take exactly one block. */
#define GSEC_AES_BLOCK_LEN 16u

/** AES-128 key length in bytes. Ten rounds. */
#define GSEC_AES128_KEY_LEN 16u

/** AES-192 key length in bytes. Twelve rounds. */
#define GSEC_AES192_KEY_LEN 24u

/** AES-256 key length in bytes. Fourteen rounds. */
#define GSEC_AES256_KEY_LEN 32u

/**
 * Expanded schedule capacity: fourteen rounds plus the initial key,
 * sixteen bytes each.
 */
#define GSEC_AES_SCHEDULE_LEN 240u

/**
 * @brief Caller-owned expanded key.
 *
 * Allocate it on the stack or in caller-owned memory. Do not read the
 * fields. The schedule is key material until ::gsec_aes_encrypt_wipe.
 */
typedef struct GSEC_Aes {
  unsigned char round_key[GSEC_AES_SCHEDULE_LEN]; ///< Round keys. Secret.
  unsigned nrounds;            ///< 10, 12, or 14. Public. Follows the key length.
  uint32_t magic;              ///< Set by init, cleared by wipe.
} GSEC_Aes;

/**
 * @brief Expand a key for encrypt and decrypt.
 *
 * Wipes @p ctx first. @p key_len is 16, 24, or 32. Any other length is
 * ::GSEC_ERR_INVALID and the context is wiped.
 *
 * @param ctx Context. NULL is ::GSEC_ERR_INVALID.
 * @param key Key bytes. NULL is ::GSEC_ERR_INVALID.
 * @param key_len 16, 24, or 32.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_aes_encrypt_init(GSEC_Aes * ctx, const void * key,
    size_t key_len);

/**
 * @brief Encrypt one block. The context stays live.
 *
 * @param ctx A context ::gsec_aes_encrypt_init returned ::GSEC_OK for,
 *   and that wipe has not cleared. Any other object is ::GSEC_ERR_INVALID
 *   and nothing is written.
 * @param in Exactly ::GSEC_AES_BLOCK_LEN bytes.
 * @param out Exactly ::GSEC_AES_BLOCK_LEN bytes. May be @p in.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_aes_encrypt_block(const GSEC_Aes * ctx,
    const void * in, void * out);

/**
 * @brief Decrypt one block. The context stays live.
 *
 * The context is the one ::gsec_aes_encrypt_init prepared. Decrypt uses
 * the same schedule.
 *
 * @param ctx A live context. Any other object is ::GSEC_ERR_INVALID.
 * @param in Exactly ::GSEC_AES_BLOCK_LEN bytes.
 * @param out Exactly ::GSEC_AES_BLOCK_LEN bytes. May be @p in.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_aes_decrypt_block(const GSEC_Aes * ctx,
    const void * in, void * out);

/**
 * @brief Encrypt one block from the key, then wipe the schedule.
 *
 * @param key Key bytes.
 * @param key_len 16, 24, or 32.
 * @param in Exactly ::GSEC_AES_BLOCK_LEN bytes.
 * @param out Exactly ::GSEC_AES_BLOCK_LEN bytes. May be @p in.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_aes_encrypt(const void * key, size_t key_len,
    const void * in, void * out);

/**
 * @brief Decrypt one block from the key, then wipe the schedule.
 *
 * @param key Key bytes.
 * @param key_len 16, 24, or 32.
 * @param in Exactly ::GSEC_AES_BLOCK_LEN bytes.
 * @param out Exactly ::GSEC_AES_BLOCK_LEN bytes. May be @p in.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_aes_decrypt(const void * key, size_t key_len,
    const void * in, void * out);

/**
 * @brief Destroy an expanded key.
 *
 * NULL is ::GSEC_ERR_INVALID. Any other pointer is wiped and the call
 * returns ::GSEC_OK, including a context that was never live.
 *
 * @param ctx Context.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_aes_encrypt_wipe(GSEC_Aes * ctx);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_AES_H */
