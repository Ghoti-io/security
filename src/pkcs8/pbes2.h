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
 * @file
 *
 * PBES2, shared by encrypted PKCS#8 and PKCS#12. The password bytes are
 * used as given: PKCS#12 has already turned them into its BMP string.
 */

#ifndef GHOTI_IO_GSEC_PBES2_H
#define GHOTI_IO_GSEC_PBES2_H

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/der.h>

#include <stddef.h>

/* A million iterations is a hostile file, not a password. */
#define GSEC_PBES2_ITER_MAX 10000000u

GSEC_Result gsec_pbes2_decrypt(const GSEC_Der * alg, const void * ct,
    size_t ct_len, const void * password, size_t password_len, void * out,
    size_t out_cap, size_t * out_len);

#endif /* GHOTI_IO_GSEC_PBES2_H */
