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
 * @file der.h
 *
 * One strict DER value.
 *
 * This is the encoding certificates use. It lives here until a
 * certificates library takes it. The reader accepts one tag-length-value
 * and rejects an indefinite length, a length that is longer than it has
 * to be, and a tag number written in the long form when the short form
 * would do. It does not allocate. The value pointer addresses the
 * caller's buffer.
 */

#ifndef GHOTI_IO_GSEC_DER_H
#define GHOTI_IO_GSEC_DER_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Universal class. */
#define GSEC_DER_UNIVERSAL 0u

/** Application class. */
#define GSEC_DER_APPLICATION 1u

/** Context-specific class. */
#define GSEC_DER_CONTEXT 2u

/** Private class. */
#define GSEC_DER_PRIVATE 3u

/**
 * @brief One DER value, viewed inside the buffer that holds it.
 *
 * @p value addresses the contents, after the tag and the length. @p total_len
 * is the number of bytes from the first tag byte through the end of the
 * contents. A constructed value's contents are more DER values; this reader
 * does not walk them.
 */
typedef struct GSEC_Der {
  unsigned tag_class;             ///< 0 universal through 3 private.
  unsigned constructed;           ///< 1 when the contents are further DER.
  unsigned number;                ///< Tag number.
  const unsigned char * value;    ///< Contents. Not a copy.
  size_t value_len;               ///< Length of @p value.
  size_t total_len;               ///< Tag, length, and contents, in bytes.
} GSEC_Der;

/**
 * @brief Read one DER value from the front of a buffer.
 *
 * Bytes after the value are not an error. The caller advances by
 * @p out->total_len. An empty buffer, a truncated value, an indefinite
 * length, and a non-minimal length or tag are ::GSEC_ERR_CORRUPT.
 *
 * @param buf Buffer. NULL only when @p len is 0.
 * @param len Length of @p buf.
 * @param out View. Not NULL.
 * @return ::GSEC_OK, ::GSEC_ERR_CORRUPT, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_der_tlv(const void * buf, size_t len, GSEC_Der * out);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_DER_H */
