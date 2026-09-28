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
 * @file md5.h
 *
 * MD5, as RFC 1321 specifies it.
 *
 * This function does not provide collision resistance. Collisions against
 * MD5 are practical, including chosen-prefix collisions. It is here because
 * an ICC profile identifier is the MD5 of the profile with three fields
 * zeroed, and because a certificate signed with it still has to be hashed
 * so a validator can reject the algorithm for that reason rather than
 * because it cannot compute the digest. Do not use it for a new signature,
 * a new MAC, or a password. A new digest is SHA-256. A new MAC is
 * HMAC-SHA-256. A new password hash is Argon2id. HMAC does not take MD5.
 *
 * The message length is public. A length that does not fit in the 64-bit
 * bit counter wipes the context and returns ::GSEC_ERR_LIMIT.
 * ::gsec_md5_final wipes the context after writing the digest. There is
 * no function that prints a context.
 */

#ifndef GHOTI_IO_GSEC_MD5_H
#define GHOTI_IO_GSEC_MD5_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Digest length in bytes. */
#define GSEC_MD5_DIGEST_LEN 16u

/** Compression block length in bytes. */
#define GSEC_MD5_BLOCK_LEN 64u

/**
 * @brief Caller-owned MD5 context.
 *
 * Allocate it on the stack or in caller-owned memory. Do not read the
 * fields. Final, and an update that hits the length limit, leave every
 * byte zero.
 */
typedef struct GSEC_Md5 {
  uint32_t state[4];           ///< Chaining value. Secret when the input is.
  uint64_t nbits;              ///< Message length in bits, excluding padding.
  unsigned char block[GSEC_MD5_BLOCK_LEN]; ///< Partial block not yet compressed.
  size_t block_len;            ///< Bytes used in ::GSEC_Md5::block.
  uint32_t magic;              ///< Set by init, cleared by final and by a limit error.
} GSEC_Md5;

/**
 * @brief Begin a hash.
 *
 * Wipes @p ctx first, so a reused object does not keep the previous message.
 *
 * @param ctx Context. NULL is ::GSEC_ERR_INVALID.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_md5_init(GSEC_Md5 * ctx);

/**
 * @brief Absorb the next slice of the message.
 *
 * @param ctx A context ::gsec_md5_init has prepared and ::gsec_md5_final
 *   has not yet finished. Any other object is ::GSEC_ERR_INVALID and is not
 *   written.
 * @param data The slice. NULL with @p n of 0 is success and absorbs nothing.
 *   NULL with @p n greater than 0 is ::GSEC_ERR_INVALID.
 * @param n Byte length of @p data. The running total, in bits, must fit in
 *   64 bits. Past that is ::GSEC_ERR_LIMIT and the context is wiped.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, or ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_md5_update(GSEC_Md5 * ctx, const void * data,
    size_t n);

/**
 * @brief Finish and wipe the context.
 *
 * @param ctx A context ::gsec_md5_init returned ::GSEC_OK for, and
 *   that final has not already finished. It is wiped on success. A
 *   context that is not live is ::GSEC_ERR_INVALID and is not written.
 * @param out Exactly ::GSEC_MD5_DIGEST_LEN bytes. NULL is
 *   ::GSEC_ERR_INVALID and the context is left live, so the caller can
 *   correct the pointer and finish.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_md5_final(GSEC_Md5 * ctx, unsigned char * out);

/**
 * @brief Hash one contiguous message.
 *
 * Equivalent to init, update, final on a context this function allocates
 * on its own stack and wipes before returning.
 *
 * @param data Message. NULL with @p n of 0 hashes the empty message.
 * @param n Message length in bytes.
 * @param out Exactly ::GSEC_MD5_DIGEST_LEN bytes.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, or ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_md5(const void * data, size_t n,
    unsigned char * out);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_MD5_H */
