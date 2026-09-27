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
 * @file aes_ctr.h
 *
 * AES in CTR mode, as NIST SP 800-38A specifies the mode, at 128, 192,
 * and 256 bits.
 *
 * The counter block is 16 bytes and is public: its length and the
 * direction it increments are part of the call. ::GSEC_AES_CTR_BE
 * increments it as a big-endian integer, which is the NIST counter.
 * ::GSEC_AES_CTR_LE increments it as a little-endian integer, which is
 * the counter WinZip AES uses. The keystream is secret. Final, and the
 * one-shot function, wipe the schedule and any unused keystream.
 *
 * A length of zero is success and does not read the buffers.
 */

#ifndef GHOTI_IO_GSEC_AES_CTR_H
#define GHOTI_IO_GSEC_AES_CTR_H

#include <ghoti.io/security/aes.h>
#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Increment the counter block as a big-endian integer. NIST SP 800-38A. */
#define GSEC_AES_CTR_BE 1u

/** Increment the counter block as a little-endian integer. WinZip AES. */
#define GSEC_AES_CTR_LE 2u

/**
 * @brief Caller-owned CTR context.
 *
 * Allocate it on the stack or in caller-owned memory. Do not read the
 * fields. The schedule and the unused keystream are secret until wipe.
 */
typedef struct GSEC_Aes_Ctr {
  GSEC_Aes aes;                              ///< Expanded key.
  unsigned char counter[GSEC_AES_BLOCK_LEN]; ///< Next counter block. Public.
  unsigned char stream[GSEC_AES_BLOCK_LEN];  ///< Unused keystream. Secret.
  size_t offset;                             ///< Bytes already used in ::GSEC_Aes_Ctr::stream.
  uint32_t direction;                        ///< ::GSEC_AES_CTR_BE or ::GSEC_AES_CTR_LE.
  uint32_t magic;                            ///< Set by init, cleared by wipe.
} GSEC_Aes_Ctr;

/**
 * @brief Expand the key and set the initial counter block.
 *
 * Wipes @p ctx first. The counter is copied. It is incremented only as
 * keystream is produced.
 *
 * @param ctx Context. NULL is ::GSEC_ERR_INVALID.
 * @param key Key bytes.
 * @param key_len 16, 24, or 32.
 * @param counter Exactly ::GSEC_AES_BLOCK_LEN bytes. NULL is
 *   ::GSEC_ERR_INVALID.
 * @param direction ::GSEC_AES_CTR_BE or ::GSEC_AES_CTR_LE.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_aes_ctr_init(GSEC_Aes_Ctr * ctx, const void * key,
    size_t key_len, const void * counter, uint32_t direction);

/**
 * @brief XOR the next slice with keystream.
 *
 * @param ctx A live context.
 * @param in Plaintext or ciphertext. NULL with @p n of 0 is success.
 * @param out The other side. May be @p in. A partial overlap is
 *   ::GSEC_ERR_INVALID and the context stays live.
 * @param n Byte length.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_aes_ctr_update(GSEC_Aes_Ctr * ctx, const void * in,
    void * out, size_t n);

/**
 * @brief One-shot CTR. The schedule does not outlive the call.
 *
 * @param key Key bytes.
 * @param key_len 16, 24, or 32.
 * @param counter Exactly ::GSEC_AES_BLOCK_LEN bytes.
 * @param direction ::GSEC_AES_CTR_BE or ::GSEC_AES_CTR_LE.
 * @param in Input. NULL with @p n of 0 is success.
 * @param out Output. May be @p in.
 * @param n Byte length.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_aes_ctr(const void * key, size_t key_len,
    const void * counter, uint32_t direction, const void * in, void * out,
    size_t n);

/**
 * @brief Destroy the schedule and any unused keystream.
 *
 * @param ctx Context. NULL is ::GSEC_ERR_INVALID. Any other pointer is
 *   wiped.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_aes_ctr_wipe(GSEC_Aes_Ctr * ctx);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_AES_CTR_H */
