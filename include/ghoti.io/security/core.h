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
 * @file core.h
 *
 * Result codes, limits, and the version this build reports.
 *
 * No function here, and no function in this library, formats key material
 * into a string. ::gsec_result_string returns one of a fixed set of static
 * strings. There is no `_dump` for a key, a private scalar, or a derived
 * secret: that would be a disclosure primitive with a test suite guaranteeing
 * it works. See documentation/design.md.
 */

#ifndef GHOTI_IO_GSEC_CORE_H
#define GHOTI_IO_GSEC_CORE_H

#include <ghoti.io/security/allocator.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Result of an operation.
 *
 * Zero is success. ::GSEC_RESULT_COUNT closes the enum so a test can check
 * the string table is complete.
 *
 * ::GSEC_ERR_MISMATCH is the one addition to the suite's fixed vocabulary.
 * A tag, a MAC, or a signature that does not match is the answer a
 * cryptographic check exists to give. Folding it into ::GSEC_ERR_INVALID
 * would make "the caller passed NULL" and "the tag is wrong" one result,
 * and a missing `!` on a boolean would make the wrong tag look like success.
 * Verification returns this status. It does not return a boolean.
 */
typedef enum {
  GSEC_OK = 0,          ///< The operation succeeded.
  GSEC_ERR_IO,          ///< A read, write, or the entropy source failed.
  GSEC_ERR_FORMAT,      ///< Well-formed bytes, but not a format handled here.
  GSEC_ERR_UNSUPPORTED, ///< The format is known and the feature is not
                        ///< implemented.
  GSEC_ERR_LIMIT,       ///< A ::GSEC_Limits field was exceeded.
  GSEC_ERR_CORRUPT,     ///< The bytes are not a valid encoding of this format.
  GSEC_ERR_OOM,         ///< The allocator returned NULL.
  GSEC_ERR_INVALID,     ///< A caller-supplied argument is wrong.
  GSEC_ERR_INTERNAL,    ///< The library's own invariant failed.
  GSEC_ERR_MISMATCH,    ///< A comparison, MAC, tag, or signature did not match.
  GSEC_RESULT_COUNT
} GSEC_Result;

/**
 * @brief Static description of a result code.
 *
 * The string is never NULL, never allocated, and never contains caller data.
 *
 * @param result The result code, including values outside the enum.
 * @return A static string.
 */
GSEC_API const char * gsec_result_string(GSEC_Result result);

/**
 * @brief Caps on quantities a caller can ask the library to produce.
 *
 * NULL at a call means these defaults. The only cap phase 0 enforces is
 * ::GSEC_Limits::max_random_bytes, because that is the only call that can be
 * asked to run without a bound the caller already paid for. A cap nothing
 * checks is not a promise, so later primitives add their fields in the commit
 * that enforces them.
 */
typedef struct GSEC_Limits {
  size_t max_random_bytes; ///< Most bytes one ::gsec_random_bytes call returns.
                           ///< Default 1 MiB.
} GSEC_Limits;

/**
 * @brief Fill in the default limits.
 *
 * @param limits Structure to populate. NULL is ignored.
 */
GSEC_API void gsec_limits_default(GSEC_Limits * limits);

/**
 * @brief This build's version, as the string the Makefile generated.
 *
 * @return A static string, never NULL. "0.0.0", or "0.0.0-dev" when BRANCH
 *   was overridden.
 */
GSEC_API const char * gsec_version_string(void);

/**
 * @brief This build's version, packed as ::GSEC_MAKE_VERSION packs it.
 *
 * @return `(major << 16) | (minor << 8) | patch`.
 */
GSEC_API unsigned gsec_version_number(void);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_CORE_H */
