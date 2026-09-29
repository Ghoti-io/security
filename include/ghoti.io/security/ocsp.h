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
 * A critical extension this parser does not understand is rejected: the
 * response's own at parse time, and the answered SingleResponse's by
 * ::gsec_ocsp_status, which is where a per-entry one can matter. A
 * critical extension on some *other* certificate's entry is not
 * examined, because it says nothing about this one and refusing the
 * whole response for it would let an unrelated entry deny service.
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
  /** producedAt, as seconds since 1970-01-01 UTC. */
  int64_t produced_at;
} GSEC_Ocsp;

/**
 * @brief One certificate's entry in a response.
 *
 * @p this_update and @p next_update are what make a response's age
 * visible. A signed response stays valid forever otherwise, which is to
 * say a captured "good" answer can be replayed until the responder's
 * certificate expires. @p have_next_update is 0 when the response omits
 * nextUpdate, which RFC 6960 permits and which means the responder has
 * newer information available at all times.
 *
 * @p revoked_at is meaningful only when @p status is
 * ::GSEC_OCSP_REVOKED.
 */
typedef struct GSEC_Ocsp_Single {
  uint32_t status;
  int64_t this_update;
  int64_t next_update;
  int have_next_update;
  int64_t revoked_at;
} GSEC_Ocsp_Single;

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
 * not in the response is ::GSEC_ERR_MISMATCH.
 *
 * **Freshness is the caller's, and it is not optional.** This function
 * reports what the response says; it has no clock. A response is a
 * statement about the instant in @p out->this_update, and replaying an
 * old one is the cheapest attack on revocation there is. Compare
 * @p out->this_update and, when @p out->have_next_update is set,
 * @p out->next_update against the time the caller already had to supply
 * to ::gsec_x509_path.
 *
 * Nothing here evaluates a delegated responder either: @p ocsp must have
 * been signed by the issuer itself, which ::gsec_ocsp_signed_by checks. A
 * response signed by a responder certificate the issuer delegated to -
 * with id-kp-OCSPSigning, which ::gsec_x509_purpose can test - fails
 * closed rather than being accepted on the delegate's authority.
 *
 * @param out Filled on ::GSEC_OK. Not NULL.
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH, ::GSEC_ERR_CORRUPT, or
 *   ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_ocsp_status(const GSEC_Ocsp * ocsp, uint32_t hash,
    const void * name_hash, size_t name_hash_len, const void * key_hash,
    size_t key_hash_len, const void * serial, size_t serial_len,
    GSEC_Ocsp_Single * out);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_OCSP_H */
