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
 * This is a password hash for storage. It is not PBKDF2. The salt is
 * the caller's 16 bytes. The cost is public. A password longer than
 * ::GSEC_BCRYPT_PASSWORD_MAX is ::GSEC_ERR_INVALID rather than silently
 * truncated.
 *
 * The key is the password bytes followed by a zero byte.
 * ::gsec_bcrypt is the $2b$ rule, and it is also $2y$: every byte is
 * unsigned. ::gsec_bcrypt_2a is that schedule with crypt_blowfish's
 * collision tweak. When the sign-extending schedule would have produced
 * the same subkeys and a later byte in a group had its high bit set,
 * bit 16 of the first subkey is flipped before the salt is mixed in.
 * ::gsec_bcrypt_2x is the sign-extending schedule itself. A byte at or
 * above 128 is widened through a signed char, and those words are the
 * key on every mix, including the later rounds. A password whose bytes
 * are all below 128 hashes the same way under all three functions.
 *
 * EksBlowfish indexes its S-boxes with bytes that depend on the
 * password. That is not constant-time, and this function is not in the
 * constant-time gate. The hash is broken for a new system. Old hashes
 * still name it.
 *
 * The output is the 24-byte ciphertext. A modular-crypt string stores
 * 23 of those bytes. This function does not format that string.
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
 * @brief Hash a password with bcrypt ($2b$).
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
 * @brief Hash a password with bcrypt ($2a$).
 *
 * The arguments are the same as ::gsec_bcrypt. The difference is the
 * collision tweak described in the file comment.
 */
GSEC_API GSEC_Result gsec_bcrypt_2a(const void * password, size_t password_len,
    const void * salt, size_t salt_len, uint32_t cost, void * hash,
    size_t hash_len);

/**
 * @brief Hash a password with bcrypt ($2x$).
 *
 * The arguments are the same as ::gsec_bcrypt. The key words are the
 * sign-extended ones described in the file comment. This exists to check
 * a hash the old code produced. A new hash should not use it.
 */
GSEC_API GSEC_Result gsec_bcrypt_2x(const void * password, size_t password_len,
    const void * salt, size_t salt_len, uint32_t cost, void * hash,
    size_t hash_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_BCRYPT_H */
