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
 * @file hmac.h
 *
 * HMAC, as FIPS 198-1 and RFC 2104 specify it, over SHA-1, SHA-256,
 * SHA-384, and SHA-512.
 *
 * The hash is chosen by the caller and is public. The key is not. A key
 * longer than the hash block is hashed down to one digest, then padded.
 * Final wipes the context, including the outer pad. ::gsec_hmac_verify
 * compares the MAC with ::gsec_equal and returns ::GSEC_ERR_MISMATCH when
 * it differs. There is no function that prints a key or a MAC.
 *
 * SHA-1 here has the same limit as ::gsec_sha1: the digest can be computed,
 * and it is not collision resistant.
 */

#ifndef GHOTI_IO_GSEC_HMAC_H
#define GHOTI_IO_GSEC_HMAC_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>
#include <ghoti.io/security/sha1.h>
#include <ghoti.io/security/sha256.h>
#include <ghoti.io/security/sha384.h>
#include <ghoti.io/security/sha512.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** HMAC over SHA-1. */
#define GSEC_HMAC_SHA1 1u

/** HMAC over SHA-256. */
#define GSEC_HMAC_SHA256 2u

/** HMAC over SHA-384. */
#define GSEC_HMAC_SHA384 3u

/** HMAC over SHA-512. */
#define GSEC_HMAC_SHA512 4u

/**
 * @brief Caller-owned HMAC context.
 *
 * Allocate it on the stack or in caller-owned memory. Do not read the
 * fields: after ::gsec_hmac_init the outer pad is key material. Final
 * leaves every byte zero.
 */
typedef struct GSEC_Hmac {
  union {
    GSEC_Sha1 sha1;       ///< Inner hash when the algorithm is SHA-1.
    GSEC_Sha256 sha256;   ///< Inner hash when the algorithm is SHA-256.
    GSEC_Sha384 sha384;   ///< Inner hash when the algorithm is SHA-384.
    GSEC_Sha512 sha512;   ///< Inner hash when the algorithm is SHA-512.
  } inner;
  unsigned char opad[GSEC_SHA512_BLOCK_LEN]; ///< Key xor 0x5c, block-sized.
  size_t block_len;       ///< Block length of the chosen hash. Public.
  size_t digest_len;      ///< Digest length of the chosen hash. Public.
  uint32_t hash;          ///< ::GSEC_HMAC_SHA1 or one of the other ids.
  uint32_t magic;         ///< Set by init, cleared by final.
} GSEC_Hmac;

/**
 * @brief Begin a MAC.
 *
 * Wipes @p ctx first. A key longer than the block is reduced with the
 * chosen hash before the pads are built. An empty key is a key of length
 * zero, which RFC 2104 allows.
 *
 * @param ctx Context. NULL is ::GSEC_ERR_INVALID.
 * @param hash ::GSEC_HMAC_SHA1, ::GSEC_HMAC_SHA256, ::GSEC_HMAC_SHA384, or
 *   ::GSEC_HMAC_SHA512. Any other value wipes @p ctx and is
 *   ::GSEC_ERR_INVALID.
 * @param key Key bytes. NULL only when @p key_len is 0.
 * @param key_len Length of @p key.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_hmac_init(GSEC_Hmac * ctx, uint32_t hash,
    const void * key, size_t key_len);

/**
 * @brief Absorb the next slice of the message.
 *
 * @param ctx A context ::gsec_hmac_init has prepared and ::gsec_hmac_final
 *   has not yet finished.
 * @param data The slice. NULL with @p n of 0 absorbs nothing. NULL with
 *   @p n greater than 0 is ::GSEC_ERR_INVALID.
 * @param n Byte length of @p data.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, or ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_hmac_update(GSEC_Hmac * ctx, const void * data,
    size_t n);

/**
 * @brief Finish and wipe the context.
 *
 * @param ctx A live context. It is wiped on success. A context that is
 *   not live is ::GSEC_ERR_INVALID and is not written.
 * @param out The MAC. The length is the digest length of the hash chosen
 *   at init. NULL is ::GSEC_ERR_INVALID and the context is left live.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_hmac_final(GSEC_Hmac * ctx, unsigned char * out);

/**
 * @brief MAC one contiguous message.
 *
 * Equivalent to init, update, final on a context this function allocates
 * on its own stack and wipes before returning.
 *
 * @param hash The hash id accepted by ::gsec_hmac_init.
 * @param key Key bytes. NULL only when @p key_len is 0.
 * @param key_len Length of @p key.
 * @param data Message. NULL with @p n of 0 MACs the empty message.
 * @param n Message length in bytes.
 * @param out The MAC. The length is the digest length of @p hash.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, or ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_hmac(uint32_t hash, const void * key, size_t key_len,
    const void * data, size_t n, unsigned char * out);

/**
 * @brief MAC a message and compare the result with ::gsec_equal.
 *
 * @p mac_len must be the digest length of @p hash. A different length is
 * ::GSEC_ERR_INVALID and is not reported as a mismatch. A MAC of the right
 * length that differs is ::GSEC_ERR_MISMATCH.
 *
 * @param hash The hash id accepted by ::gsec_hmac_init.
 * @param key Key bytes. NULL only when @p key_len is 0.
 * @param key_len Length of @p key.
 * @param data Message. NULL with @p n of 0 MACs the empty message.
 * @param n Message length in bytes.
 * @param mac The MAC to check.
 * @param mac_len Length of @p mac.
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH, ::GSEC_ERR_INVALID, or
 *   ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_hmac_verify(uint32_t hash, const void * key,
    size_t key_len, const void * data, size_t n, const void * mac,
    size_t mac_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_HMAC_H */
