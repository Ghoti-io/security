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
 * @file hkdf.h
 *
 * HKDF, as RFC 5869 specifies it, over HMAC-SHA-1, HMAC-SHA-256,
 * HMAC-SHA-384, and HMAC-SHA-512.
 *
 * This is the derivation TLS 1.3 uses for high-entropy input. It is not
 * PBKDF2. PBKDF2 is deliberately slow and is for a low-entropy password.
 * Substituting one for the other is a different function, and a caller who
 * wanted the slow one will not get it here.
 *
 * A salt of length zero is the RFC default: HashLen zero bytes. The output
 * of expand is at most 255 digests. There is no function that prints a
 * PRK or the derived key.
 */

#ifndef GHOTI_IO_GSEC_HKDF_H
#define GHOTI_IO_GSEC_HKDF_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/hmac.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** HKDF with HMAC-SHA-1. The same value as ::GSEC_HMAC_SHA1. */
#define GSEC_HKDF_SHA1 GSEC_HMAC_SHA1

/** HKDF with HMAC-SHA-256. The same value as ::GSEC_HMAC_SHA256. */
#define GSEC_HKDF_SHA256 GSEC_HMAC_SHA256

/** HKDF with HMAC-SHA-384. The same value as ::GSEC_HMAC_SHA384. */
#define GSEC_HKDF_SHA384 GSEC_HMAC_SHA384

/** HKDF with HMAC-SHA-512. The same value as ::GSEC_HMAC_SHA512. */
#define GSEC_HKDF_SHA512 GSEC_HMAC_SHA512

/**
 * @brief HKDF-Extract: PRK = HMAC-Hash(salt, IKM).
 *
 * The PRK is one digest long. A salt of length zero is HashLen zero bytes,
 * which is what RFC 5869 specifies when the salt is not provided.
 *
 * @param hash ::GSEC_HKDF_SHA1, ::GSEC_HKDF_SHA256, ::GSEC_HKDF_SHA384, or
 *   ::GSEC_HKDF_SHA512.
 * @param salt Salt. NULL only when @p salt_len is 0.
 * @param salt_len Length of @p salt. Zero selects the RFC default salt.
 * @param ikm Input keying material. NULL only when @p ikm_len is 0.
 * @param ikm_len Length of @p ikm.
 * @param prk Output. One digest of @p hash. NULL is ::GSEC_ERR_INVALID.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_hkdf_extract(uint32_t hash, const void * salt,
    size_t salt_len, const void * ikm, size_t ikm_len, unsigned char * prk);

/**
 * @brief HKDF-Expand.
 *
 * T(i) = HMAC-Hash(PRK, T(i-1) || info || i), and the output is the first
 * @p okm_len bytes of T(1) || T(2) || .... @p okm_len above 255 digests is
 * ::GSEC_ERR_LIMIT and writes nothing.
 *
 * @param hash The hash id accepted by ::gsec_hkdf_extract.
 * @param prk The output of extract, or another key of the caller's choosing.
 *   NULL only when @p prk_len is 0.
 * @param prk_len Length of @p prk.
 * @param info Context string. NULL only when @p info_len is 0.
 * @param info_len Length of @p info.
 * @param okm Output. NULL only when @p okm_len is 0.
 * @param okm_len Number of bytes to write. Zero is success and writes nothing.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, or ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_hkdf_expand(uint32_t hash, const void * prk,
    size_t prk_len, const void * info, size_t info_len, unsigned char * okm,
    size_t okm_len);

/**
 * @brief Extract, then expand.
 *
 * Equivalent to ::gsec_hkdf_extract and ::gsec_hkdf_expand. The PRK is
 * allocated on this function's stack and wiped before return.
 *
 * @param hash The hash id accepted by ::gsec_hkdf_extract.
 * @param salt Salt. NULL only when @p salt_len is 0.
 * @param salt_len Length of @p salt. Zero selects the RFC default salt.
 * @param ikm Input keying material. NULL only when @p ikm_len is 0.
 * @param ikm_len Length of @p ikm.
 * @param info Context string. NULL only when @p info_len is 0.
 * @param info_len Length of @p info.
 * @param okm Output. NULL only when @p okm_len is 0.
 * @param okm_len Number of bytes to write. Zero is success and writes nothing.
 *   Above 255 digests is ::GSEC_ERR_LIMIT.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, or ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_hkdf(uint32_t hash, const void * salt,
    size_t salt_len, const void * ikm, size_t ikm_len, const void * info,
    size_t info_len, unsigned char * okm, size_t okm_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_HKDF_H */
