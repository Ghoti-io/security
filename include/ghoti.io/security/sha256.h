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
 * @file sha256.h
 *
 * SHA-256, as FIPS 180-4 specifies it.
 *
 * The message length is public. The number of blocks follows that length,
 * and this function does not try to hide it. What it does not do is branch
 * on a message byte or index a table with one. `make check-ct` hashes a
 * poisoned buffer and memcheck reports either of those.
 *
 * A context holds the chaining value of what has been hashed so far. When
 * the input is secret, that value is secret. ::gsec_sha256_final wipes the
 * context after writing the digest. A length that will not fit in the
 * 64-bit bit counter wipes it and returns ::GSEC_ERR_LIMIT, so the caller
 * does not keep a context that accepted a prefix and then refused the rest.
 * There is no function that prints a context.
 */

#ifndef GHOTI_IO_GSEC_SHA256_H
#define GHOTI_IO_GSEC_SHA256_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Digest length in bytes. */
#define GSEC_SHA256_DIGEST_LEN 32u

/** Compression block length in bytes. */
#define GSEC_SHA256_BLOCK_LEN 64u

/**
 * @brief Caller-owned SHA-256 context.
 *
 * Allocate it on the stack or in caller-owned memory. Do not read the
 * fields: after ::gsec_sha256_init they are the chaining value. Pass the
 * same object to update and final. Final, and an update that hits the
 * length limit, leave every byte zero.
 */
typedef struct GSEC_Sha256 {
  uint32_t state[8];           ///< Chaining value. Secret when the input is.
  uint64_t nbits;              ///< Message length in bits, excluding padding.
  unsigned char block[GSEC_SHA256_BLOCK_LEN]; ///< Partial block not yet compressed.
  size_t block_len;            ///< Bytes used in ::GSEC_Sha256::block.
  uint32_t magic;              ///< Set by init, cleared by final and by a limit error.
} GSEC_Sha256;

/**
 * @brief Begin a hash.
 *
 * Wipes @p ctx first, so a reused object does not keep the previous message.
 *
 * @param ctx Context. NULL is ::GSEC_ERR_INVALID.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_sha256_init(GSEC_Sha256 * ctx);

/**
 * @brief Absorb the next slice of the message.
 *
 * @param ctx A context ::gsec_sha256_init has prepared and ::gsec_sha256_final
 *   has not yet finished. Any other object is ::GSEC_ERR_INVALID and is not
 *   written.
 * @param data The slice. NULL with @p n of 0 is success and absorbs nothing.
 *   NULL with @p n greater than 0 is ::GSEC_ERR_INVALID.
 * @param n Byte length of @p data. The running total, in bits, must fit in
 *   64 bits. Past that is ::GSEC_ERR_LIMIT and the context is wiped.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, or ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_sha256_update(GSEC_Sha256 * ctx, const void * data,
    size_t n);

/**
 * @brief Finish and wipe the context.
 *
 * @param ctx A context ::gsec_sha256_init returned ::GSEC_OK for, and
 *   that final has not already finished. It is wiped on success. A
 *   context that is not live is ::GSEC_ERR_INVALID and is not written.
 * @param out Exactly ::GSEC_SHA256_DIGEST_LEN bytes. NULL is
 *   ::GSEC_ERR_INVALID and the context is left live, so the caller can
 *   correct the pointer and finish.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_sha256_final(GSEC_Sha256 * ctx, unsigned char * out);

/**
 * @brief Hash one contiguous message.
 *
 * Equivalent to init, update, final on a context this function allocates
 * on its own stack and wipes before returning.
 *
 * @param data Message. NULL with @p n of 0 hashes the empty message.
 * @param n Message length in bytes.
 * @param out Exactly ::GSEC_SHA256_DIGEST_LEN bytes.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, or ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_sha256(const void * data, size_t n,
    unsigned char * out);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_SHA256_H */
