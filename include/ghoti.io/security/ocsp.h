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
 * @file ocsp.h
 *
 * A basic OCSP response, as RFC 6960 specifies it.
 *
 * Parsing and the signature check live here. Fetching the response does
 * not. The caller supplies the issuer-name hash and the issuer-key hash.
 * A critical extension this parser does not understand is rejected.
 * The pointers address the caller's buffer, except an ECDSA signature,
 * which is copied into the result.
 */

#ifndef GHOTI_IO_GSEC_OCSP_H
#define GHOTI_IO_GSEC_OCSP_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>
#include <ghoti.io/security/x509.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The certificate is not revoked. */
#define GSEC_OCSP_GOOD 0u

/** The certificate is revoked. */
#define GSEC_OCSP_REVOKED 1u

/** The responder does not know the certificate. */
#define GSEC_OCSP_UNKNOWN 2u

/**
 * @brief A parsed basic OCSP response. The view is valid while the DER is.
 */
typedef struct GSEC_Ocsp {
  const unsigned char * tbs;
  size_t tbs_len;
  uint32_t sig_key;
  uint32_t sig_hash;
  const unsigned char * sig;
  size_t sig_len;
  unsigned char ecdsa_raw[96];
  const unsigned char * responses;
  size_t responses_len;
} GSEC_Ocsp;

/**
 * @brief Parse one successful basic OCSP response.
 *
 * A response status other than successful is ::GSEC_ERR_UNSUPPORTED.
 * Only id-pkix-ocsp-basic is read.
 *
 * @param der DER encoding. NULL only when @p len is 0.
 * @param len Length of @p der. Above ::GSEC_X509_DER_MAX is
 *   ::GSEC_ERR_LIMIT.
 * @param out View. Not NULL.
 * @return ::GSEC_OK, ::GSEC_ERR_CORRUPT, ::GSEC_ERR_UNSUPPORTED,
 *   ::GSEC_ERR_LIMIT, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_ocsp_parse(const void * der, size_t len,
    GSEC_Ocsp * out);

/**
 * @brief Check that @p issuer's key signed @p ocsp.
 *
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_ocsp_signed_by(const GSEC_Ocsp * ocsp,
    const GSEC_X509 * issuer);

/**
 * @brief Look up one certificate in the response.
 *
 * @p hash is ::GSEC_HMAC_SHA1, ::GSEC_HMAC_SHA256, ::GSEC_HMAC_SHA384, or
 * ::GSEC_HMAC_SHA512, and both hashes are that digest. A CertID that is
 * not in the response is ::GSEC_ERR_MISMATCH. When the status is
 * ::GSEC_OCSP_REVOKED and @p revoked_at is not NULL, it receives the
 * revocation time.
 *
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH, ::GSEC_ERR_CORRUPT, or
 *   ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_ocsp_status(const GSEC_Ocsp * ocsp, uint32_t hash,
    const void * name_hash, size_t name_hash_len, const void * key_hash,
    size_t key_hash_len, const void * serial, size_t serial_len,
    uint32_t * status, int64_t * revoked_at);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_OCSP_H */
