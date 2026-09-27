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
 * @file argon2.h
 *
 * Argon2, as RFC 9106 specifies it, version 0x13.
 *
 * This is a password hash for storage. It is not PBKDF2 and it is not
 * scrypt. The salt is the caller's, at least 8 bytes. The memory cost,
 * the pass count, and the lane count are public. The memory those
 * parameters ask for does not depend on the password.
 *
 * Argon2d, and Argon2id after the first half of the first pass, read
 * memory at an index derived from the password. That read is not
 * constant-time. Argon2i's indexes are a function of the public
 * parameters. None of the three is in the constant-time gate.
 *
 * Lanes are the algorithm's parallelism parameter. The work runs on
 * the calling thread. BLAKE2b is internal to this hash and is not a
 * separate function.
 */

#ifndef GHOTI_IO_GSEC_ARGON2_H
#define GHOTI_IO_GSEC_ARGON2_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Argon2d. Data-dependent addressing. RFC 9106 type 0. */
#define GSEC_ARGON2_D 0u

/** Argon2i. Data-independent addressing. RFC 9106 type 1. */
#define GSEC_ARGON2_I 1u

/** Argon2id. RFC 9106 type 2. The type to use for password storage. */
#define GSEC_ARGON2_ID 2u

/** Largest working set, in kibibytes. */
#define GSEC_ARGON2_MEMORY_MAX (32u * 1024u)

/** Shortest salt, in bytes. */
#define GSEC_ARGON2_SALT_MIN 8u

/** Shortest tag, in bytes. */
#define GSEC_ARGON2_TAG_MIN 4u

/** Longest tag this function will write, in bytes. */
#define GSEC_ARGON2_TAG_MAX 1024u

/**
 * @brief Hash a password with Argon2.
 *
 * @param type ::GSEC_ARGON2_D, ::GSEC_ARGON2_I, or ::GSEC_ARGON2_ID.
 * @param password Password bytes. NULL only when @p password_len is 0.
 * @param password_len Length of @p password.
 * @param salt Salt. At least ::GSEC_ARGON2_SALT_MIN bytes. The caller's
 *   nonce.
 * @param salt_len Length of @p salt.
 * @param secret Optional secret. NULL only when @p secret_len is 0.
 * @param secret_len Length of @p secret.
 * @param ad Optional associated data. NULL only when @p ad_len is 0.
 * @param ad_len Length of @p ad.
 * @param memory_kib Memory cost in kibibytes. At least eight times
 *   @p lanes, and at most ::GSEC_ARGON2_MEMORY_MAX.
 * @param passes Number of passes. At least 1.
 * @param lanes Lane count. At least 1. This is the algorithm parameter,
 *   not a thread count.
 * @param tag Output.
 * @param tag_len From ::GSEC_ARGON2_TAG_MIN to ::GSEC_ARGON2_TAG_MAX.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, or ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_argon2(uint32_t type, const void * password,
    size_t password_len, const void * salt, size_t salt_len,
    const void * secret, size_t secret_len, const void * ad, size_t ad_len,
    uint32_t memory_kib, uint32_t passes, uint32_t lanes, void * tag,
    size_t tag_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_ARGON2_H */
