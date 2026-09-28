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
 * @file bcrypt.h
 *
 * bcrypt, the EksBlowfish password hash.
 *
 * These functions check a hash an old system stored. Do not use bcrypt
 * for a new password store. A new password hash is Argon2id,
 * ::gsec_argon2 with ::GSEC_ARGON2_ID.
 *
 * ::gsec_bcrypt is $2b$, and it is also $2y$. ::gsec_bcrypt_2a checks a
 * $2a$ hash. ::gsec_bcrypt_2x checks a $2x$ hash. A new bcrypt hash, when
 * the store is already bcrypt, uses ::gsec_bcrypt. The salt is the
 * caller's 16 bytes. A password longer than ::GSEC_BCRYPT_PASSWORD_MAX
 * is ::GSEC_ERR_INVALID rather than silently truncated. The output is
 * the 24-byte ciphertext. A modular-crypt string stores 23 of those
 * bytes. This function does not format that string.
 *
 * The key schedule indexes its S-boxes with bytes that depend on the
 * password, so this is not constant-time and it is not in the
 * constant-time gate.
 */

#ifndef GHOTI_IO_GSEC_BCRYPT_H
#define GHOTI_IO_GSEC_BCRYPT_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Salt length, in bytes. */
#define GSEC_BCRYPT_SALT_LEN 16u

/** Ciphertext length, in bytes. */
#define GSEC_BCRYPT_HASH_LEN 24u

/**
 * Longest password, in bytes, not counting the zero the algorithm
 * appends. A longer password is ::GSEC_ERR_INVALID.
 */
#define GSEC_BCRYPT_PASSWORD_MAX 72u

/** Smallest accepted cost. The cost is log2 of the round count. */
#define GSEC_BCRYPT_COST_MIN 4u

/** Largest accepted cost. */
#define GSEC_BCRYPT_COST_MAX 31u

/**
 * @brief Hash a password with bcrypt ($2b$ and $2y$).
 *
 * A new password store uses Argon2id. This is for a store that already
 * uses bcrypt.
 *
 * @param password Password bytes. NULL only when @p password_len is 0.
 * @param password_len Length of @p password. At most
 *   ::GSEC_BCRYPT_PASSWORD_MAX.
 * @param salt 16-byte salt. The caller's nonce.
 * @param salt_len Must be ::GSEC_BCRYPT_SALT_LEN.
 * @param cost Log2 of the EksBlowfish round count. From
 *   ::GSEC_BCRYPT_COST_MIN to ::GSEC_BCRYPT_COST_MAX.
 * @param hash Output. 24 bytes.
 * @param hash_len Must be ::GSEC_BCRYPT_HASH_LEN.
 * @return ::GSEC_OK or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_bcrypt(const void * password, size_t password_len,
    const void * salt, size_t salt_len, uint32_t cost, void * hash,
    size_t hash_len);

/**
 * @brief Check a password against a $2a$ hash.
 *
 * Do not use this for a new hash. A store that is already bcrypt uses
 * ::gsec_bcrypt. A new password store uses Argon2id. The arguments are
 * the same as ::gsec_bcrypt.
 */
GSEC_API GSEC_Result gsec_bcrypt_2a(const void * password, size_t password_len,
    const void * salt, size_t salt_len, uint32_t cost, void * hash,
    size_t hash_len);

/**
 * @brief Check a password against a $2x$ hash.
 *
 * Do not use this for a new hash. A store that is already bcrypt uses
 * ::gsec_bcrypt. A new password store uses Argon2id. The arguments are
 * the same as ::gsec_bcrypt.
 */
GSEC_API GSEC_Result gsec_bcrypt_2x(const void * password, size_t password_len,
    const void * salt, size_t salt_len, uint32_t cost, void * hash,
    size_t hash_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_BCRYPT_H */
