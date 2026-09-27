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
 * and SHA-384.
 * The rest of the set is named in `tools/oracle/primitives.txt` and is not
 * declared until the commit that implements it. X.509, PEM, the handshake,
 * and password hashing for
 * storage are other libraries. See documentation/design.md.
 */

#ifndef GHOTI_IO_GSEC_SECURITY_H
#define GHOTI_IO_GSEC_SECURITY_H

#include <ghoti.io/security/allocator.h>
#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>
#include <ghoti.io/security/random.h>
#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/selftest.h>
#include <ghoti.io/security/sha256.h>
#include <ghoti.io/security/sha384.h>
#include <ghoti.io/security/sha512.h>

#endif /* GHOTI_IO_GSEC_SECURITY_H */
