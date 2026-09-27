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
 * DER helpers shared by PKCS#8 and X.509. Not a public header.
 */

#ifndef GHOTI_IO_GSEC_DER_INT_H
#define GHOTI_IO_GSEC_DER_INT_H

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/der.h>

#include <stddef.h>
#include <stdint.h>

int gsec_der_is(const GSEC_Der * v, unsigned tag_class, unsigned constructed,
    unsigned number);

int gsec_der_eq(const unsigned char * a, size_t a_len, const unsigned char * b,
    size_t b_len);

GSEC_Result gsec_der_next(const unsigned char ** p, size_t * left, GSEC_Der * out);

GSEC_Result gsec_der_unsigned(const GSEC_Der * v, const unsigned char ** be,
    size_t * be_len);

GSEC_Result gsec_der_bit_payload(const GSEC_Der * v, const unsigned char ** bits,
    size_t * bits_len);

GSEC_Result gsec_der_oid_ok(const GSEC_Der * v);

int gsec_der_oid_is(const GSEC_Der * v, const unsigned char * oid, size_t oid_len);

GSEC_Result gsec_der_set_sorted(const GSEC_Der * v);

GSEC_Result gsec_der_time(const GSEC_Der * v, int64_t * unix_time);

#endif /* GHOTI_IO_GSEC_DER_INT_H */
