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
 * Signature algorithm and verification shared by certificates, CRLs, and
 * OCSP. Not a public header.
 */

#ifndef GHOTI_IO_GSEC_X509_SIGNED_H
#define GHOTI_IO_GSEC_X509_SIGNED_H

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/der.h>
#include <ghoti.io/security/x509.h>

GSEC_Result x509_sig_alg(const GSEC_Der * alg, uint32_t * key, uint32_t * hash);

GSEC_Result x509_sig_bits(uint32_t key, const unsigned char * bits,
    size_t bits_len, const unsigned char ** sig, size_t * sig_len,
    unsigned char raw[96]);

GSEC_Result x509_sig_verify(uint32_t key, uint32_t hash, const unsigned char * sig,
    size_t sig_len, const unsigned char * tbs, size_t tbs_len,
    const GSEC_X509 * issuer);

#endif /* GHOTI_IO_GSEC_X509_SIGNED_H */
