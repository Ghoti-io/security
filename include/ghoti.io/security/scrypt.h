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
 * @file scrypt.h
 *
 * scrypt, as RFC 7914 specifies it.
 *
 * This is a password hash for storage. It is not PBKDF2 and it is not
 * HKDF. The salt is the caller's. N, r, and p are public: the cost is
 * the point of the function. The memory those parameters ask for does
 * not depend on the password. ROMix then reads that memory at an index
 * derived from the password. That read is not constant-time, and this
 * function is not in the constant-time gate.
 *
 * N is a power of two, at least 2. The working memory is 128*r*(N+p)
 * bytes. More than ::GSEC_SCRYPT_MEMORY_MAX is ::GSEC_ERR_LIMIT and
 * allocates nothing.
 */

#ifndef GHOTI_IO_GSEC_SCRYPT_H
#define GHOTI_IO_GSEC_SCRYPT_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Largest working set scrypt will allocate, in bytes. */
#define GSEC_SCRYPT_MEMORY_MAX (32u * 1024u * 1024u)

/**
 * @brief Derive a key from a password with scrypt.
 *
 * @param password Password bytes. NULL only when @p password_len is 0.
 * @param password_len Length of @p password.
 * @param salt Salt. NULL only when @p salt_len is 0. The caller's nonce.
 * @param salt_len Length of @p salt.
 * @param n CPU and memory cost. A power of two, at least 2.
 * @param r Block size parameter. At least 1.
 * @param p Parallelism parameter. At least 1.
 * @param dk Output. NULL only when @p dk_len is 0.
 * @param dk_len Number of bytes to write.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, or ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_scrypt(const void * password, size_t password_len,
    const void * salt, size_t salt_len, uint64_t n, uint32_t r, uint32_t p,
    void * dk, size_t dk_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_SCRYPT_H */
