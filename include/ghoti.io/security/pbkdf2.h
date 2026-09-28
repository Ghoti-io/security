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
 * @file pbkdf2.h
 *
 * PBKDF2, as RFC 8018 specifies it, with HMAC-SHA-1, HMAC-SHA-256,
 * HMAC-SHA-384, or HMAC-SHA-512 as the pseudorandom function.
 *
 * This is the derivation WinZip AES uses, and it is deliberately slow: the
 * iteration count is the cost. It is for a low-entropy password. It is not
 * HKDF. HKDF is for high-entropy input and does not iterate to waste time.
 * Substituting one for the other is a different function. HMAC-SHA-1 is
 * for an old derivation. A new one uses SHA-256 or stronger. A password
 * hash for storage is Argon2id, not this function.
 *
 * An iteration count of zero is ::GSEC_ERR_INVALID. A derived-key length
 * that needs more than 2^32-1 blocks is ::GSEC_ERR_LIMIT. There is no
 * function that prints a password or a derived key.
 */

#ifndef GHOTI_IO_GSEC_PBKDF2_H
#define GHOTI_IO_GSEC_PBKDF2_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/hmac.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** PBKDF2 with HMAC-SHA-1. The same value as ::GSEC_HMAC_SHA1. */
#define GSEC_PBKDF2_SHA1 GSEC_HMAC_SHA1

/** PBKDF2 with HMAC-SHA-256. The same value as ::GSEC_HMAC_SHA256. */
#define GSEC_PBKDF2_SHA256 GSEC_HMAC_SHA256

/** PBKDF2 with HMAC-SHA-384. The same value as ::GSEC_HMAC_SHA384. */
#define GSEC_PBKDF2_SHA384 GSEC_HMAC_SHA384

/** PBKDF2 with HMAC-SHA-512. The same value as ::GSEC_HMAC_SHA512. */
#define GSEC_PBKDF2_SHA512 GSEC_HMAC_SHA512

/**
 * @brief Derive a key from a password.
 *
 * F(P, S, c, i) is U_1 xor ... xor U_c, with U_1 = HMAC(P, S || INT(i)) and
 * each later U the HMAC of the previous one. INT(i) is four big-endian
 * bytes. The output is the concatenation of those blocks, cut to @p dk_len.
 *
 * @param hash ::GSEC_PBKDF2_SHA1, ::GSEC_PBKDF2_SHA256, ::GSEC_PBKDF2_SHA384,
 *   or ::GSEC_PBKDF2_SHA512.
 * @param password Password bytes. NULL only when @p password_len is 0.
 * @param password_len Length of @p password. Zero is an empty password,
 *   which RFC 6070 includes.
 * @param salt Salt. NULL only when @p salt_len is 0.
 * @param salt_len Length of @p salt.
 * @param iterations A positive iteration count. Zero is ::GSEC_ERR_INVALID.
 *   The count is public: the slowness is the point of the function.
 * @param dk Output. NULL only when @p dk_len is 0.
 * @param dk_len Number of bytes to write. Zero is success and writes
 *   nothing. A length that needs more than 2^32-1 blocks is
 *   ::GSEC_ERR_LIMIT and writes nothing.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, or ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_pbkdf2(uint32_t hash, const void * password,
    size_t password_len, const void * salt, size_t salt_len,
    uint32_t iterations, unsigned char * dk, size_t dk_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_PBKDF2_H */
