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
 * @file x25519.h
 *
 * X25519, as RFC 7748 specifies it.
 *
 * The caller is TLS 1.3 key agreement. The scalar and the u-coordinate
 * are each 32 bytes. The scalar is clamped inside the function. The top
 * bit of the u-coordinate is ignored, which is what the RFC specifies.
 *
 * A shared secret of all zeros is rejected and the output is wiped. RFC
 * 7748 section 6.1 requires that check: it is the result of a small-order
 * peer key, and it is not a key.
 */

#ifndef GHOTI_IO_GSEC_X25519_H
#define GHOTI_IO_GSEC_X25519_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#ifdef __cplusplus
extern "C" {
#endif

/** RFC 7748 scalar, u-coordinate, and shared-secret length. */
#define GSEC_X25519_LEN 32u

/**
 * @brief Multiply the scalar by the base point and write the public key.
 *
 * @param scalar Exactly ::GSEC_X25519_LEN bytes. Clamped as RFC 7748
 *   specifies.
 * @param out Exactly ::GSEC_X25519_LEN bytes. May alias @p scalar.
 * @return ::GSEC_OK or ::GSEC_ERR_INVALID.
 */
GSEC_API GSEC_Result gsec_x25519_public(const void * scalar, void * out);

/**
 * @brief Multiply the scalar by the peer u-coordinate.
 *
 * @param scalar Exactly ::GSEC_X25519_LEN bytes. Clamped as RFC 7748
 *   specifies.
 * @param point Peer u-coordinate, exactly ::GSEC_X25519_LEN bytes.
 * @param out Exactly ::GSEC_X25519_LEN bytes. May alias @p scalar or
 *   @p point. Wiped when the shared secret is all zeros.
 * @return ::GSEC_OK, or ::GSEC_ERR_INVALID for a null argument or for the
 *   all-zero shared secret.
 */
GSEC_API GSEC_Result gsec_x25519(const void * scalar, const void * point,
    void * out);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_X25519_H */
