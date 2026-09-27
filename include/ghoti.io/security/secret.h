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
 * @file secret.h
 *
 * Constant-time comparison, wiping, and the marks the constant-time gate reads.
 *
 * ::gsec_equal is the comparison every MAC, tag, and verifier in this library
 * uses. `memcmp` on those bytes is a defect: it returns at the first
 * differing byte, and that timing is the secret. `tools/check-secret.py`
 * rejects `memcmp` anywhere under `src/`.
 *
 * ::gsec_poison and ::gsec_unpoison are how a test tells memcheck which bytes
 * are secret. In a normal build they do nothing. Built with `GSEC_CT_TEST`
 * (`make check-ct`) they issue Valgrind client requests. Marking the secret
 * is the documentation of what is secret.
 */

#ifndef GHOTI_IO_GSEC_SECRET_H
#define GHOTI_IO_GSEC_SECRET_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Compare two regions without branching on their contents.
 *
 * The length is public: the loop always runs `n` times, and a difference in
 * the first byte takes the same path as a difference in the last. The result
 * is a status, not a boolean. ::GSEC_OK and ::GSEC_ERR_MISMATCH are the two
 * answers a well-formed call can give, and a missing `!` cannot invert them.
 *
 * A NULL pointer with `n > 0` is ::GSEC_ERR_INVALID and returns before any
 * byte is read. The pointer is the caller's, not a secret. `n == 0` is equal,
 * including when either pointer is NULL: there is nothing to compare.
 *
 * @param a First region. NULL only when @p n is 0.
 * @param b Second region. NULL only when @p n is 0.
 * @param n Number of bytes. Public.
 * @return ::GSEC_OK if every byte matches, ::GSEC_ERR_MISMATCH if any byte
 *   differs, or ::GSEC_ERR_INVALID if a pointer is NULL and @p n is not 0.
 */
GSEC_API GSEC_Result gsec_equal(const void * a, const void * b, size_t n);

/**
 * @brief Overwrite a region with zeros in a way the compiler cannot delete.
 *
 * The call goes through a volatile function pointer, so the compiler cannot
 * see that the callee is `memset` and cannot delete the write as a dead
 * store. That is the whole function: a secret that survives in a register or
 * on the stack after the caller is finished with it is still a secret.
 *
 * NULL with `n > 0` is ::GSEC_ERR_INVALID and writes nothing. NULL with
 * `n == 0`, and a non-NULL pointer with `n == 0`, succeed and write nothing.
 *
 * @param p Region to overwrite. NULL only when @p n is 0.
 * @param n Number of bytes.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID if @p p is NULL and @p n is not 0.
 */
GSEC_API GSEC_Result gsec_wipe(void * p, size_t n);

/**
 * @brief Mark a region secret for the constant-time gate.
 *
 * In a `GSEC_CT_TEST` build this is `VALGRIND_MAKE_MEM_UNDEFINED`: memcheck
 * then reports a conditional jump or a memory index that depends on these
 * bytes. In every other build it does nothing, so a caller can leave the
 * marks in test code without an `#ifdef`. NULL is ignored.
 *
 * @param p Region to mark. NULL is ignored.
 * @param n Number of bytes. Zero is ignored.
 */
GSEC_API void gsec_poison(void * p, size_t n);

/**
 * @brief Mark a region public for the constant-time gate.
 *
 * The counterpart of ::gsec_poison, for a result the caller is about to
 * branch on. ::gsec_equal and ::gsec_wipe already do this for the status and
 * the wiped bytes when the library itself is built with `GSEC_CT_TEST`.
 * NULL is ignored.
 *
 * @param p Region to mark. NULL is ignored.
 * @param n Number of bytes. Zero is ignored.
 */
GSEC_API void gsec_unpoison(void * p, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_SECRET_H */
