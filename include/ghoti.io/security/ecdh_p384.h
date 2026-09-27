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
 * @file ecdh_p384.h
 *
 * ECDH on NIST P-384.
 *
 * The scalar, each coordinate, and the shared secret are 48 bytes,
 * big-endian. The peer public key is x then y, 96 bytes, with no
 * uncompressed-point prefix. A coordinate that is not strictly less than
 * the field prime, a point that is not on the curve, and a product that
 * is the point at infinity are rejected and the output is wiped. TLS 1.2
 * and TLS 1.3 both name this curve for key agreement.
 */

#ifndef GHOTI_IO_GSEC_ECDH_P384_H
#define GHOTI_IO_GSEC_ECDH_P384_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Scalar, coordinate, and shared-secret length. */
#define GSEC_P384_LEN 48u

/** Public key length: x coordinate, then y coordinate. */
#define GSEC_P384_PUBLIC_LEN 96u

/**
 * @brief Multiply the scalar by the base point and write the public key.
 *
 * @param scalar Exactly ::GSEC_P384_LEN bytes, big-endian.
 * @param out Exactly ::GSEC_P384_PUBLIC_LEN bytes. May alias @p scalar.
 *   Wiped when the product is the point at infinity.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID for a null argument or the point
 *   at infinity.
 */
GSEC_API GSEC_Result gsec_ecdh_p384_public(const void * scalar, void * out);

/**
 * @brief Multiply the scalar by the peer point and write the shared x.
 *
 * @param scalar Exactly ::GSEC_P384_LEN bytes, big-endian.
 * @param peer Exactly ::GSEC_P384_PUBLIC_LEN bytes, x then y.
 * @param out Exactly ::GSEC_P384_LEN bytes. May alias @p scalar or @p peer.
 *   Wiped when the peer is not a curve point or the product is the point
 *   at infinity.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_ecdh_p384(const void * scalar, const void * peer,
    void * out);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_ECDH_P384_H */
