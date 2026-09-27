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
 * @file x509.h
 *
 * An X.509 certificate and a path check, as RFC 5280 specifies them.
 *
 * This lives here until a certificates library takes it. It does not
 * depend on anything but the primitives in this library. The time is a
 * Unix second the caller already decided, not a chron instant. A DNS
 * name is compared as stored: internationalized names are the caller's
 * to turn into A-labels. Revocation is not checked. A critical extension
 * this parser does not understand is rejected. certificatePolicies is
 * read and not enforced. PKCS#12 is not a certificate and is not read
 * here.
 *
 * The pointers in the result address the certificate the caller passed
 * in, except an ECDSA signature, which is copied into the result so the
 * raw r and s have a fixed width. Do not relocate the result without
 * the certificate bytes.
 */

#ifndef GHOTI_IO_GSEC_X509_H
#define GHOTI_IO_GSEC_X509_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Largest certificate this parser will read. */
#define GSEC_X509_DER_MAX 65536u

/** Intermediates ::gsec_x509_path will walk, not counting the leaf or the anchor. */
#define GSEC_X509_CHAIN_MAX 16u

/** RSA public key. */
#define GSEC_X509_RSA 1u

/** P-256 public key, x then y. */
#define GSEC_X509_P256 2u

/** P-384 public key, x then y. */
#define GSEC_X509_P384 3u

/** Ed25519 public key. */
#define GSEC_X509_ED25519 4u

/**
 * @brief A parsed certificate. The view is valid while the DER is.
 *
 * @p key_usage bit 0 is digitalSignature. Bit 5 is keyCertSign.
 */
typedef struct GSEC_X509 {
  const unsigned char * tbs;
  size_t tbs_len;
  const unsigned char * issuer;
  size_t issuer_len;
  const unsigned char * subject;
  size_t subject_len;
  int64_t not_before;
  int64_t not_after;
  uint32_t key;
  const unsigned char * n;
  size_t n_len;
  const unsigned char * e;
  size_t e_len;
  const unsigned char * point;
  size_t point_len;
  uint32_t sig_key;
  uint32_t sig_hash;
  const unsigned char * sig;
  size_t sig_len;
  unsigned char ecdsa_raw[96];
  int ca;
  int basic_constraints;
  int path_len_set;
  uint32_t path_len;
  int key_usage_set;
  unsigned key_usage;
  const unsigned char * san;
  size_t san_len;
  int dns_san;
  const unsigned char * name_constraints;
  size_t name_constraints_len;
} GSEC_X509;

/**
 * @brief Parse one certificate.
 *
 * @param der DER encoding. NULL only when @p len is 0.
 * @param len Length of @p der. Above ::GSEC_X509_DER_MAX is
 *   ::GSEC_ERR_LIMIT.
 * @param out View. Not NULL.
 * @return ::GSEC_OK, ::GSEC_ERR_CORRUPT, ::GSEC_ERR_UNSUPPORTED,
 *   ::GSEC_ERR_LIMIT, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_x509_parse(const void * der, size_t len,
    GSEC_X509 * out);

/**
 * @brief Check that @p issuer's key signed @p cert.
 *
 * Names and times are not considered.
 *
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_x509_signed_by(const GSEC_X509 * cert,
    const GSEC_X509 * issuer);

/**
 * @brief Validate a chain from the leaf up to a trust anchor.
 *
 * @p mids are the intermediates, leaf's issuer first and the anchor's
 * subject last. @p mid_count of 0 means the anchor signed the leaf.
 * The anchor is trusted as a CA even when it has no basicConstraints.
 * An anchor that says it is not a CA is rejected. An intermediate must
 * be a CA and, when keyUsage is present, must have keyCertSign. Both
 * ends of the validity period are inclusive. Name constraints on dNSName
 * and directoryName are applied. Any other name-constraint type is
 * ::GSEC_ERR_UNSUPPORTED.
 *
 * @param unix_time The instant to test, as seconds since 1970-01-01 UTC.
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH, ::GSEC_ERR_CORRUPT,
 *   ::GSEC_ERR_UNSUPPORTED, ::GSEC_ERR_LIMIT, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_x509_path(const void * leaf, size_t leaf_len,
    const void * const * mids, const size_t * mid_lens, size_t mid_count,
    const void * anchor, size_t anchor_len, int64_t unix_time);

/**
 * @brief Match a DNS name against the certificate.
 *
 * subjectAltName dNSName entries are tried when any are present.
 * Otherwise the common name is tried. A wildcard is only the entire
 * leftmost label. The comparison is ASCII case-insensitive. A name that
 * is not ASCII does not match.
 *
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_x509_hostname(const GSEC_X509 * cert,
    const char * name, size_t name_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_X509_H */
