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
 * @file selftest.h
 *
 * A few known answers for every primitive this build implements.
 *
 * Optional for the caller. It does not print, and it does not return the
 * bytes it used. A failure is a status from the primitive that failed.
 */

#ifndef GHOTI_IO_GSEC_SELFTEST_H
#define GHOTI_IO_GSEC_SELFTEST_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Run the built-in known answers.
 *
 * Covers comparison, wiping, one read from the kernel generator, and the
 * SHA-256, SHA-512, and SHA-384 of the empty message and of `abc`. Later
 * primitives add their vectors here in the same commit that adds the
 * primitive.
 *
 * @return ::GSEC_OK, or the status of the first check that failed.
 */
GSEC_API GSEC_Result gsec_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_SELFTEST_H */
