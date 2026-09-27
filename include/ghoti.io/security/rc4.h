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
 * @file rc4.h
 *
 * RC4, as it was specified for TLS and for the formats that still name it.
 *
 * The cipher is broken. It is here because those formats still use it.
 * Do not use it for a new design. The permutation is indexed by secret
 * bytes, so this is not a constant-time implementation and it is not in
 * the constant-time gate.
 *
 * The key is 1 to 256 bytes. There is no drop: the first keystream byte
 * is the first output byte. A length of zero is success and does not
 * read the buffers.
 */

#ifndef GHOTI_IO_GSEC_RC4_H
#define GHOTI_IO_GSEC_RC4_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Minimum key length. */
#define GSEC_RC4_KEY_MIN 1u

/** Maximum key length. */
#define GSEC_RC4_KEY_MAX 256u

/**
 * @brief Encrypt or decrypt with RC4. The operation is the same either way.
 *
 * @param key Key bytes. NULL is ::GSEC_ERR_INVALID.
 * @param key_len 1 to 256.
 * @param in Input. NULL only when @p len is 0.
 * @param len Number of bytes.
 * @param out Output, @p len bytes. May be @p in. A partial overlap is
 *   ::GSEC_ERR_INVALID.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_rc4(const void * key, size_t key_len, const void * in,
    size_t len, void * out);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_RC4_H */
