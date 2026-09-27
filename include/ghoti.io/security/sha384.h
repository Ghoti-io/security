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
 * @file sha384.h
 *
 * SHA-384, as FIPS 180-4 specifies it.
 *
 * The compression is SHA-512. The initial value is the SHA-384 value from
 * FIPS 180-4 section 5.3.4, and the digest is the first 48 bytes of the
 * chaining value. Hashing the same bytes with ::gsec_sha512 and keeping
 * 48 bytes is a different function: the initial values differ.
 *
 * The message length is public. A length that does not fit in the 128-bit
 * counter wipes the context and returns ::GSEC_ERR_LIMIT. ::gsec_sha384_final
 * wipes the context, including the 16 bytes of chaining value it did not
 * write to the digest. There is no function that prints a context.
 */

#ifndef GHOTI_IO_GSEC_SHA384_H
#define GHOTI_IO_GSEC_SHA384_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Digest length in bytes. */
#define GSEC_SHA384_DIGEST_LEN 48u

/** Compression block length in bytes. Same block as SHA-512. */
#define GSEC_SHA384_BLOCK_LEN 128u

/**
 * @brief Caller-owned SHA-384 context.
 *
 * Allocate it on the stack or in caller-owned memory. Do not read the
 * fields. Final, and an update that hits the length limit, leave every
 * byte zero.
 */
typedef struct GSEC_Sha384 {
  uint64_t state[8];            ///< Chaining value. Secret when the input is.
  uint64_t nbits_hi;            ///< High 64 bits of the message length in bits.
  uint64_t nbits_lo;            ///< Low 64 bits of the message length in bits.
  unsigned char block[GSEC_SHA384_BLOCK_LEN]; ///< Partial block not yet compressed.
  size_t block_len;             ///< Bytes used in ::GSEC_Sha384::block.
  uint32_t magic;               ///< Set by init, cleared by final and by a limit error.
} GSEC_Sha384;

/**
 * @brief Begin a hash.
 *
 * Wipes @p ctx first, so a reused object does not keep the previous message.
 *
 * @param ctx Context. NULL is ::GSEC_ERR_INVALID.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_sha384_init(GSEC_Sha384 * ctx);

/**
 * @brief Absorb the next slice of the message.
 *
 * @param ctx A context ::gsec_sha384_init has prepared and ::gsec_sha384_final
 *   has not yet finished. Any other object is ::GSEC_ERR_INVALID and is not
 *   written.
 * @param data The slice. NULL with @p n of 0 is success and absorbs nothing.
 *   NULL with @p n greater than 0 is ::GSEC_ERR_INVALID.
 * @param n Byte length of @p data. The running total, in bits, must fit in
 *   128 bits. Past that is ::GSEC_ERR_LIMIT and the context is wiped.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, or ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_sha384_update(GSEC_Sha384 * ctx, const void * data,
    size_t n);

/**
 * @brief Finish and wipe the context.
 *
 * Writes ::GSEC_SHA384_DIGEST_LEN bytes. The rest of the chaining value is
 * wiped with the context and is not part of the digest.
 *
 * @param ctx A context ::gsec_sha384_init returned ::GSEC_OK for, and
 *   that final has not already finished. It is wiped on success. A
 *   context that is not live is ::GSEC_ERR_INVALID and is not written.
 * @param out Exactly ::GSEC_SHA384_DIGEST_LEN bytes. NULL is
 *   ::GSEC_ERR_INVALID and the context is left live, so the caller can
 *   correct the pointer and finish.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_sha384_final(GSEC_Sha384 * ctx, unsigned char * out);

/**
 * @brief Hash one contiguous message.
 *
 * Equivalent to init, update, final on a context this function allocates
 * on its own stack and wipes before returning.
 *
 * @param data Message. NULL with @p n of 0 hashes the empty message.
 * @param n Message length in bytes.
 * @param out Exactly ::GSEC_SHA384_DIGEST_LEN bytes.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, or ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_sha384(const void * data, size_t n,
    unsigned char * out);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_SHA384_H */
