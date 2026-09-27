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
 * @file random.h
 *
 * The only function in this library that produces key material.
 *
 * It reads the kernel generator and nothing else. cutil's Mersenne Twister is
 * not a substitute, and this header does not call it. There is no userspace
 * generator behind a failure, no cache, and no pool: those fail across fork,
 * clone, and early boot, and no caller this library is being built for needs
 * them.
 *
 * A short read is retried. Any other failure wipes whatever was already
 * written and returns ::GSEC_ERR_IO. The caller must not read @p out unless
 * the call returned ::GSEC_OK.
 *
 * Linux uses `getrandom` without `GRND_NONBLOCK`, so the call waits until the
 * kernel generator is initialised rather than failing and tempting a
 * fallback. macOS uses `getentropy`. Windows uses `BCryptGenRandom` with
 * `BCRYPT_USE_SYSTEM_PREFERRED_RNG`.
 */

#ifndef GHOTI_IO_GSEC_RANDOM_H
#define GHOTI_IO_GSEC_RANDOM_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fill a buffer from the kernel generator.
 *
 * @param out Buffer to fill. NULL is ::GSEC_ERR_INVALID when @p n is not 0.
 *   On failure the whole buffer is wiped when @p out is non-NULL, including
 *   any bytes the kernel had already returned.
 * @param n Number of bytes. Zero succeeds and writes nothing. Larger than
 *   ::GSEC_Limits::max_random_bytes is ::GSEC_ERR_LIMIT and writes nothing.
 * @param limits Caps. NULL means ::gsec_limits_default.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, ::GSEC_ERR_LIMIT, or ::GSEC_ERR_IO.
 *   ::GSEC_ERR_IO means the generator failed. It does not mean a partial
 *   buffer is usable.
 */
GSEC_API GSEC_Result gsec_random_bytes(void * out, size_t n,
    const GSEC_Limits * limits);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_RANDOM_H */
