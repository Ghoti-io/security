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
 * @file rsa.h
 *
 * RSA signature verification. PKCS#1 v1.5 and PSS, public exponent only.
 *
 * The modulus is at most 4096 bits. A leading zero byte is ignored, which
 * is how an ASN.1 integer is written when its top bit is set. The
 * signature is the same length as the modulus after those zeros are
 * removed. PKCS#1 v1.5 accepts only the DER DigestInfo, including the
 * NULL, and at least eight 0xff padding bytes. PSS takes the salt length
 * as a parameter and encodes one bit shorter than the modulus, which is
 * what RFC 8017 specifies. MD5 and SHA-1 are accepted so an old
 * certificate can be checked and then rejected for the algorithm. There
 * is no private-key operation here.
 */

#ifndef GHOTI_IO_GSEC_RSA_H
#define GHOTI_IO_GSEC_RSA_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** MD5. Not collision resistant. */
#define GSEC_RSA_MD5 1u

/** SHA-1. Not collision resistant. */
#define GSEC_RSA_SHA1 2u

/** SHA-256. */
#define GSEC_RSA_SHA256 3u

/** SHA-384. */
#define GSEC_RSA_SHA384 4u

/** SHA-512. */
#define GSEC_RSA_SHA512 5u

/** Largest modulus, in bytes, after a leading zero is removed. */
#define GSEC_RSA_MODULUS_MAX 512u

/**
 * @brief Verify an RSASSA-PKCS1-v1_5 signature.
 *
 * @param hash ::GSEC_RSA_MD5, ::GSEC_RSA_SHA1, ::GSEC_RSA_SHA256,
 *   ::GSEC_RSA_SHA384, or ::GSEC_RSA_SHA512.
 * @param n Modulus, big-endian. A leading 0x00 is ignored.
 * @param n_len Length of @p n.
 * @param e Public exponent, big-endian. It must be odd and at least 3.
 * @param e_len Length of @p e.
 * @param msg Message. NULL only when @p msg_len is 0.
 * @param msg_len Message length in bytes.
 * @param sig Signature, big-endian, the same length as the modulus after
 *   a leading zero is removed.
 * @param sig_len Length of @p sig.
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH, ::GSEC_ERR_INVALID, or
 *   ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_rsa_pkcs1_v15_verify(uint32_t hash, const void * n,
    size_t n_len, const void * e, size_t e_len, const void * msg,
    size_t msg_len, const void * sig, size_t sig_len);

/**
 * @brief Verify an RSASSA-PSS signature.
 *
 * @p mgf_hash is the MGF1 hash. TLS uses the same hash as @p hash, and
 * the salt length equal to that hash's digest length.
 *
 * @param hash The message hash. One of the ids accepted by
 *   ::gsec_rsa_pkcs1_v15_verify.
 * @param mgf_hash The MGF1 hash. The same set.
 * @param n Modulus, big-endian. A leading 0x00 is ignored.
 * @param n_len Length of @p n.
 * @param e Public exponent, big-endian. It must be odd and at least 3.
 * @param e_len Length of @p e.
 * @param msg Message. NULL only when @p msg_len is 0.
 * @param msg_len Message length in bytes.
 * @param sig Signature, big-endian.
 * @param sig_len Length of @p sig.
 * @param salt_len Expected salt length in bytes.
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH, ::GSEC_ERR_INVALID, or
 *   ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_rsa_pss_verify(uint32_t hash, uint32_t mgf_hash,
    const void * n, size_t n_len, const void * e, size_t e_len,
    const void * msg, size_t msg_len, const void * sig, size_t sig_len,
    size_t salt_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_RSA_H */
