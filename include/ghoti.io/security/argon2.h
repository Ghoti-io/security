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
 * Argon2. ::gsec_argon2 is version 0x13, as RFC 9106 specifies it, and
 * ::GSEC_ARGON2_ID is the type for a new password store.
 * ::gsec_argon2_version also accepts version 0x10, which is for checking
 * an old hash. Do not use 0x10 for a new hash: that version overwrites a
 * block on later passes instead of mixing it in. A PHC string is
 * ::gsec_argon2_phc and ::gsec_argon2_phc_verify. A string with no
 * version is 0x10, and it is checked as that old version.
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

/** Argon2 version 1.2.1. Later passes overwrite a block. */
#define GSEC_ARGON2_VERSION_10 0x10u

/** Argon2 version 1.3. RFC 9106. Later passes mix the old block in. */
#define GSEC_ARGON2_VERSION_13 0x13u

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

/**
 * @brief Hash a password with Argon2 at a chosen version.
 *
 * Version 0x10 checks an old hash. A new hash uses
 * ::GSEC_ARGON2_VERSION_13, or calls ::gsec_argon2.
 *
 * @param version ::GSEC_ARGON2_VERSION_10 or ::GSEC_ARGON2_VERSION_13.
 *   Any other value is ::GSEC_ERR_INVALID.
 * The remaining arguments match ::gsec_argon2.
 */
GSEC_API GSEC_Result gsec_argon2_version(uint32_t version, uint32_t type,
    const void * password, size_t password_len, const void * salt,
    size_t salt_len, const void * secret, size_t secret_len, const void * ad,
    size_t ad_len, uint32_t memory_kib, uint32_t passes, uint32_t lanes,
    void * tag, size_t tag_len);

/**
 * @brief Hash a password and write the PHC string.
 *
 * The string is `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<tag>`, with the
 * type, the decimal version, and the parameters filled in. The salt and
 * the tag are standard base64 with the padding omitted. The secret and
 * the associated data are not written into the string. @p encoded is
 * terminated with a zero byte when the call succeeds, and @p encoded_len
 * does not count that byte.
 *
 * @param tag_len Tag length, from ::GSEC_ARGON2_TAG_MIN to
 *   ::GSEC_ARGON2_TAG_MAX. The usual length is 32.
 * @param encoded Output. Not NULL.
 * @param encoded_cap Capacity, including the terminating zero.
 * @param encoded_len Receives the string length. Not written on failure.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, or ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_argon2_phc(uint32_t version, uint32_t type,
    const void * password, size_t password_len, const void * salt,
    size_t salt_len, const void * secret, size_t secret_len, const void * ad,
    size_t ad_len, uint32_t memory_kib, uint32_t passes, uint32_t lanes,
    size_t tag_len, void * encoded, size_t encoded_cap, size_t * encoded_len);

/**
 * @brief Check a password against a PHC string.
 *
 * A string with no `v=` field is version 0x10. The secret and the
 * associated data are the caller's, because the string does not carry
 * them. A wrong password is ::GSEC_ERR_MISMATCH.
 *
 * @param encoded The PHC string. Not necessarily terminated.
 * @param encoded_len Length of @p encoded, not counting a terminator.
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH, ::GSEC_ERR_CORRUPT,
 *   ::GSEC_ERR_INVALID, or ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_argon2_phc_verify(const void * encoded,
    size_t encoded_len, const void * password, size_t password_len,
    const void * secret, size_t secret_len, const void * ad, size_t ad_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_ARGON2_H */
