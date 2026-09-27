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
 * @file pkcs8.h
 *
 * An unencrypted PKCS#8 private key.
 *
 * This lives here until a certificates library takes it. The pointers in
 * the result address the caller's buffer. They are the key, so the caller
 * wipes that buffer. A password-encrypted key is ::GSEC_ERR_UNSUPPORTED.
 * PKCS#12 is a different encoding and is not read here.
 *
 * RSA yields the modulus, the public exponent, and the private exponent.
 * P-256 and P-384 yield the scalar. Ed25519 yields the 32-byte seed.
 */

#ifndef GHOTI_IO_GSEC_PKCS8_H
#define GHOTI_IO_GSEC_PKCS8_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** RSA modulus, public exponent, and private exponent. */
#define GSEC_PKCS8_RSA 1u

/** P-256 scalar, 32 bytes. */
#define GSEC_PKCS8_P256 2u

/** P-384 scalar, 48 bytes. */
#define GSEC_PKCS8_P384 3u

/** Ed25519 seed, 32 bytes. */
#define GSEC_PKCS8_ED25519 4u

/**
 * @brief Key material viewed inside the PKCS#8 buffer.
 *
 * Unused pointers are NULL and the matching length is 0. The view is
 * valid while the buffer passed to ::gsec_pkcs8_parse is.
 */
typedef struct GSEC_Pkcs8 {
  uint32_t kind;                  ///< ::GSEC_PKCS8_RSA and the others.
  const unsigned char * n;        ///< RSA modulus.
  size_t n_len;
  const unsigned char * e;        ///< RSA public exponent.
  size_t e_len;
  const unsigned char * d;        ///< RSA private exponent.
  size_t d_len;
  const unsigned char * scalar;   ///< Elliptic-curve scalar or Ed25519 seed.
  size_t scalar_len;
} GSEC_Pkcs8;

/**
 * @brief Parse an unencrypted PrivateKeyInfo.
 *
 * @param der DER bytes. NULL only when @p len is 0.
 * @param len Length of @p der.
 * @param out View. Not NULL. Wiped of its own pointers on failure, which
 *   does not wipe the caller's key buffer.
 * @return ::GSEC_OK, ::GSEC_ERR_CORRUPT, ::GSEC_ERR_UNSUPPORTED, or
 *   ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_pkcs8_parse(const void * der, size_t len,
    GSEC_Pkcs8 * out);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_PKCS8_H */
