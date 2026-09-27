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
 * @file security.h
 *
 * Umbrella header for the Ghoti.io Security library.
 *
 * Primitives only: comparison, wiping, the entropy call, SHA-256, SHA-512,
 * SHA-384, SHA-1, MD5, HMAC over the SHA hashes, HKDF, PBKDF2, AES,
 * AES-CTR, AES-CBC, AES-GCM, ChaCha20-Poly1305, X25519, Ed25519, P-256 and
 * P-384 ECDH,
 * ECDSA P-256, ECDSA P-384, RSA signature verification, scrypt, bcrypt, Argon2,
 * and the certificate encodings (strict DER, PEM, unencrypted PKCS#8, and
 * X.509). Those encodings live here until a certificates library takes them.
 * The handshake does not. See documentation/design.md.
 */

#ifndef GHOTI_IO_GSEC_SECURITY_H
#define GHOTI_IO_GSEC_SECURITY_H

#include <ghoti.io/security/aes.h>
#include <ghoti.io/security/argon2.h>
#include <ghoti.io/security/aes_cbc.h>
#include <ghoti.io/security/aes_ctr.h>
#include <ghoti.io/security/aes_gcm.h>
#include <ghoti.io/security/chacha20_poly1305.h>
#include <ghoti.io/security/allocator.h>
#include <ghoti.io/security/hkdf.h>
#include <ghoti.io/security/hmac.h>
#include <ghoti.io/security/pbkdf2.h>
#include <ghoti.io/security/pem.h>
#include <ghoti.io/security/pkcs8.h>
#include <ghoti.io/security/core.h>
#include <ghoti.io/security/der.h>
#include <ghoti.io/security/des.h>
#include <ghoti.io/security/ecdsa_p256.h>
#include <ghoti.io/security/ecdsa_p384.h>
#include <ghoti.io/security/ecdh_p256.h>
#include <ghoti.io/security/ecdh_p384.h>
#include <ghoti.io/security/ed25519.h>
#include <ghoti.io/security/macros.h>
#include <ghoti.io/security/md5.h>
#include <ghoti.io/security/random.h>
#include <ghoti.io/security/bcrypt.h>
#include <ghoti.io/security/rc4.h>
#include <ghoti.io/security/rsa.h>
#include <ghoti.io/security/scrypt.h>
#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/selftest.h>
#include <ghoti.io/security/sha1.h>
#include <ghoti.io/security/sha256.h>
#include <ghoti.io/security/sha384.h>
#include <ghoti.io/security/sha512.h>
#include <ghoti.io/security/x25519.h>
#include <ghoti.io/security/x509.h>

#endif /* GHOTI_IO_GSEC_SECURITY_H */
