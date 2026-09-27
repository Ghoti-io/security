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
 * @file namespace.h
 *
 * Maps every public name of this library into its version namespace.
 *
 * Kept in one file rather than beside each declaration: a type rename has to
 * be in effect before any struct tag that uses the name, and an internal
 * header may define such a tag without including the public header that
 * declares the typedef.
 *
 * `make check-symbols` fails if an exported symbol is missing from this list.
 *
 * See CONVENTIONS.md section 4.
 */

#ifndef GHOTI_IO_GSEC_NAMESPACE_H
#define GHOTI_IO_GSEC_NAMESPACE_H

#include <ghoti.io/security/libver.h>

/// @cond HIDDEN_SYMBOLS

/* Public types. GCU_* names are cutil's; cutil has already renamed them. */
#define GSEC_Allocator GHOTIIO_SECURITY(GSEC_Allocator)
#define GSEC_Limits GHOTIIO_SECURITY(GSEC_Limits)
#define GSEC_Result GHOTIIO_SECURITY(GSEC_Result)
#define GSEC_Sha256 GHOTIIO_SECURITY(GSEC_Sha256)

#define gsec_allocator_default GHOTIIO_SECURITY(gsec_allocator_default)
#define gsec_equal GHOTIIO_SECURITY(gsec_equal)
#define gsec_limits_default GHOTIIO_SECURITY(gsec_limits_default)
#define gsec_poison GHOTIIO_SECURITY(gsec_poison)
#define gsec_random_bytes GHOTIIO_SECURITY(gsec_random_bytes)
#define gsec_result_string GHOTIIO_SECURITY(gsec_result_string)
#define gsec_selftest GHOTIIO_SECURITY(gsec_selftest)
#define gsec_sha256 GHOTIIO_SECURITY(gsec_sha256)
#define gsec_sha256_final GHOTIIO_SECURITY(gsec_sha256_final)
#define gsec_sha256_init GHOTIIO_SECURITY(gsec_sha256_init)
#define gsec_sha256_update GHOTIIO_SECURITY(gsec_sha256_update)
#define gsec_unpoison GHOTIIO_SECURITY(gsec_unpoison)
#define gsec_version_number GHOTIIO_SECURITY(gsec_version_number)
#define gsec_version_string GHOTIIO_SECURITY(gsec_version_string)
#define gsec_wipe GHOTIIO_SECURITY(gsec_wipe)

/// @endcond

#endif /* GHOTI_IO_GSEC_NAMESPACE_H */
