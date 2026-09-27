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
 * @file crl.h
 *
 * A certificate revocation list, as RFC 5280 specifies it.
 *
 * Parsing and the signature check live here. Fetching the list does not.
 * A critical extension this parser does not understand is rejected.
 * The pointers address the caller's buffer, except an ECDSA signature,
 * which is copied into the result.
 */

#ifndef GHOTI_IO_GSEC_CRL_H
#define GHOTI_IO_GSEC_CRL_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>
#include <ghoti.io/security/x509.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief A parsed CRL. The view is valid while the DER is.
 */
typedef struct GSEC_Crl {
  const unsigned char * tbs;
  size_t tbs_len;
  const unsigned char * issuer;
  size_t issuer_len;
  int64_t this_update;
  int next_set;
  int64_t next_update;
  uint32_t sig_key;
  uint32_t sig_hash;
  const unsigned char * sig;
  size_t sig_len;
  unsigned char ecdsa_raw[96];
  const unsigned char * revoked;
  size_t revoked_len;
} GSEC_Crl;

/**
 * @brief Parse one CertificateList.
 *
 * @param der DER encoding. NULL only when @p len is 0.
 * @param len Length of @p der. Above ::GSEC_X509_DER_MAX is
 *   ::GSEC_ERR_LIMIT.
 * @param out View. Not NULL.
 * @return ::GSEC_OK, ::GSEC_ERR_CORRUPT, ::GSEC_ERR_UNSUPPORTED,
 *   ::GSEC_ERR_LIMIT, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_crl_parse(const void * der, size_t len,
    GSEC_Crl * out);

/**
 * @brief Check that @p issuer's key signed @p crl.
 *
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_crl_signed_by(const GSEC_Crl * crl,
    const GSEC_X509 * issuer);

/**
 * @brief Report whether @p serial appears on the list.
 *
 * @p serial is the unsigned magnitude. A hit is ::GSEC_OK. An absent
 * serial is ::GSEC_ERR_MISMATCH.
 */
GSEC_API GSEC_Result gsec_crl_contains(const GSEC_Crl * crl, const void * serial,
    size_t serial_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_CRL_H */
