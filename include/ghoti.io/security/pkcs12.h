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
 * @file pkcs12.h
 *
 * A PKCS#12 PFX, as RFC 7292 specifies it.
 *
 * The password is UTF-8. The MAC turns it into the BMP string RFC 7292
 * requires, including the trailing two zero bytes, then uses the PKCS#12
 * key derivation of Appendix B with id 3 and HMAC. A PBES2 bag uses the
 * UTF-8 bytes themselves, which is what OpenSSL writes. A character
 * outside the Basic Multilingual Plane is rejected. A wrong password
 * fails the MAC.
 *
 * Shrouded keys and encrypted cert bags use PBES2. RC2 is rejected.
 * The key and the certificates are views of @p scratch, or of the input
 * when a bag was not encrypted. At most ::GSEC_PKCS12_CERT_MAX
 * certificates are returned.
 */

#ifndef GHOTI_IO_GSEC_PKCS12_H
#define GHOTI_IO_GSEC_PKCS12_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Certificates one call will return. */
#define GSEC_PKCS12_CERT_MAX 8u

/**
 * @brief A private key and the certificates that travelled with it.
 *
 * @p key is a PrivateKeyInfo. Each certificate is a full Certificate.
 */
typedef struct GSEC_Pkcs12 {
  const unsigned char * key;
  size_t key_len;
  const unsigned char * certs[GSEC_PKCS12_CERT_MAX];
  size_t cert_lens[GSEC_PKCS12_CERT_MAX];
  size_t cert_count;
} GSEC_Pkcs12;

/**
 * @brief Open a PFX.
 *
 * @param der PFX bytes. NULL only when @p len is 0.
 * @param len Length of @p der.
 * @param password UTF-8 password. NULL only when @p password_len is 0.
 * @param password_len Length of @p password.
 * @param scratch Space for decrypted bags. Not NULL.
 * @param scratch_cap Capacity of @p scratch. A ciphertext that does not
 *   fit is ::GSEC_ERR_LIMIT. Wiped when the MAC or the padding fails.
 * @param out Views. Not NULL.
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH, ::GSEC_ERR_UNSUPPORTED,
 *   ::GSEC_ERR_CORRUPT, ::GSEC_ERR_LIMIT, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_pkcs12_open(const void * der, size_t len,
    const void * password, size_t password_len, void * scratch,
    size_t scratch_cap, GSEC_Pkcs12 * out);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_PKCS12_H */
