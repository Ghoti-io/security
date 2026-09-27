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
 * CertificateList. Revoked serials stay in the caller's buffer and are
 * walked when asked.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/crl.h>

#include "../der/der_int.h"
#include "signed.h"

#include <string.h>

static int same_uint(const unsigned char * a, size_t a_len, const unsigned char * b,
    size_t b_len) {
  while (a_len > 0 && a[0] == 0) {
    a++;
    a_len--;
  }
  while (b_len > 0 && b[0] == 0) {
    b++;
    b_len--;
  }
  return gsec_der_eq(a, a_len, b, b_len);
}

static GSEC_Result skip_extensions(const unsigned char * p, size_t n) {
  GSEC_Der seq;
  GSEC_Result result;
  const unsigned char * cursor;
  size_t left;

  result = gsec_der_tlv(p, n, &seq);
  if (result != GSEC_OK || seq.total_len != n ||
      !gsec_der_is(&seq, GSEC_DER_UNIVERSAL, 1, 16)) {
    return GSEC_ERR_CORRUPT;
  }
  cursor = seq.value;
  left = seq.value_len;
  while (left != 0) {
    GSEC_Der ext;
    GSEC_Der field;
    GSEC_Der oid;
    const unsigned char * ep;
    size_t eleft;
    static const unsigned char OID_CRL_NUMBER[] = {0x55, 0x1d, 0x14};
    result = gsec_der_next(&cursor, &left, &ext);
    if (result != GSEC_OK || !gsec_der_is(&ext, GSEC_DER_UNIVERSAL, 1, 16)) {
      return GSEC_ERR_CORRUPT;
    }
    ep = ext.value;
    eleft = ext.value_len;
    result = gsec_der_next(&ep, &eleft, &oid);
    if (result != GSEC_OK || gsec_der_oid_ok(&oid) != GSEC_OK) {
      return GSEC_ERR_CORRUPT;
    }
    result = gsec_der_next(&ep, &eleft, &field);
    if (result != GSEC_OK) {
      return result;
    }
    if (gsec_der_is(&field, GSEC_DER_UNIVERSAL, 0, 1)) {
      int critical = field.value_len == 1 && field.value[0] == 0xff;
      if (field.value_len != 1 || (field.value[0] != 0 && field.value[0] != 0xff)) {
        return GSEC_ERR_CORRUPT;
      }
      if (critical && !gsec_der_oid_is(&oid, OID_CRL_NUMBER, sizeof OID_CRL_NUMBER)) {
        return GSEC_ERR_UNSUPPORTED;
      }
      result = gsec_der_next(&ep, &eleft, &field);
      if (result != GSEC_OK) {
        return result;
      }
    }
    if (eleft != 0 || !gsec_der_is(&field, GSEC_DER_UNIVERSAL, 0, 4)) {
      return GSEC_ERR_CORRUPT;
    }
  }
  return GSEC_OK;
}

GSEC_Result gsec_crl_parse(const void * der, size_t len, GSEC_Crl * out) {
  GSEC_Der seq;
  GSEC_Der tbs;
  GSEC_Der alg;
  GSEC_Der sig;
  GSEC_Der field;
  GSEC_Result result;
  const unsigned char * p;
  size_t left;
  const unsigned char * bits;
  size_t bits_len;
  uint32_t inner_key;
  uint32_t inner_hash;
  int saw_revoked = 0;

  if (out == NULL || (der == NULL && len != 0)) {
    return GSEC_ERR_INVALID;
  }
  memset(out, 0, sizeof *out);
  if (len == 0 || len > GSEC_X509_DER_MAX) {
    return len == 0 ? GSEC_ERR_CORRUPT : GSEC_ERR_LIMIT;
  }
  result = gsec_der_tlv(der, len, &seq);
  if (result != GSEC_OK || seq.total_len != len ||
      !gsec_der_is(&seq, GSEC_DER_UNIVERSAL, 1, 16)) {
    return GSEC_ERR_CORRUPT;
  }
  p = seq.value;
  left = seq.value_len;
  result = gsec_der_next(&p, &left, &tbs);
  if (result != GSEC_OK || !gsec_der_is(&tbs, GSEC_DER_UNIVERSAL, 1, 16)) {
    return GSEC_ERR_CORRUPT;
  }
  out->tbs = p - tbs.total_len;
  out->tbs_len = tbs.total_len;
  result = gsec_der_next(&p, &left, &alg);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_der_next(&p, &left, &sig);
  if (result != GSEC_OK || left != 0) {
    return GSEC_ERR_CORRUPT;
  }
  p = tbs.value;
  left = tbs.value_len;
  result = gsec_der_next(&p, &left, &field);
  if (result != GSEC_OK) {
    return result;
  }
  if (gsec_der_is(&field, GSEC_DER_UNIVERSAL, 0, 2)) {
    const unsigned char * be;
    size_t be_len;
    result = gsec_der_unsigned(&field, &be, &be_len);
    if (result != GSEC_OK || be_len != 1 || be[0] != 1) {
      return GSEC_ERR_CORRUPT;
    }
    result = gsec_der_next(&p, &left, &field);
    if (result != GSEC_OK) {
      return result;
    }
  }
  result = x509_sig_alg(&field, &inner_key, &inner_hash);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_der_next(&p, &left, &field);
  if (result != GSEC_OK || !gsec_der_is(&field, GSEC_DER_UNIVERSAL, 1, 16)) {
    return GSEC_ERR_CORRUPT;
  }
  out->issuer = p - field.total_len;
  out->issuer_len = field.total_len;
  result = gsec_der_next(&p, &left, &field);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_der_time(&field, &out->this_update);
  if (result != GSEC_OK) {
    return result;
  }
  if (left != 0) {
    result = gsec_der_next(&p, &left, &field);
    if (result != GSEC_OK) {
      return result;
    }
    if (gsec_der_is(&field, GSEC_DER_UNIVERSAL, 0, 23) ||
        gsec_der_is(&field, GSEC_DER_UNIVERSAL, 0, 24)) {
      result = gsec_der_time(&field, &out->next_update);
      if (result != GSEC_OK) {
        return result;
      }
      out->next_set = 1;
    } else if (gsec_der_is(&field, GSEC_DER_UNIVERSAL, 1, 16)) {
      out->revoked = field.value;
      out->revoked_len = field.value_len;
      saw_revoked = 1;
    } else if (field.tag_class == GSEC_DER_CONTEXT && field.constructed == 1 &&
        field.number == 0) {
      result = skip_extensions(field.value, field.value_len);
      if (result != GSEC_OK || left != 0) {
        return result != GSEC_OK ? result : GSEC_ERR_CORRUPT;
      }
    } else {
      return GSEC_ERR_CORRUPT;
    }
  }
  if (out->next_set && !saw_revoked && left != 0) {
    result = gsec_der_next(&p, &left, &field);
    if (result != GSEC_OK) {
      return result;
    }
    if (gsec_der_is(&field, GSEC_DER_UNIVERSAL, 1, 16)) {
      out->revoked = field.value;
      out->revoked_len = field.value_len;
      saw_revoked = 1;
    } else if (field.tag_class == GSEC_DER_CONTEXT && field.constructed == 1 &&
        field.number == 0) {
      result = skip_extensions(field.value, field.value_len);
      if (result != GSEC_OK || left != 0) {
        return result != GSEC_OK ? result : GSEC_ERR_CORRUPT;
      }
    } else {
      return GSEC_ERR_CORRUPT;
    }
  }
  if (saw_revoked && left != 0) {
    result = gsec_der_next(&p, &left, &field);
    if (result != GSEC_OK) {
      return result;
    }
    if (!(field.tag_class == GSEC_DER_CONTEXT && field.constructed == 1 &&
        field.number == 0) || left != 0) {
      return GSEC_ERR_CORRUPT;
    }
    result = skip_extensions(field.value, field.value_len);
    if (result != GSEC_OK) {
      return result;
    }
  }
  result = x509_sig_alg(&alg, &out->sig_key, &out->sig_hash);
  if (result != GSEC_OK || out->sig_key != inner_key || out->sig_hash != inner_hash) {
    return result != GSEC_OK ? result : GSEC_ERR_CORRUPT;
  }
  result = gsec_der_bit_payload(&sig, &bits, &bits_len);
  if (result != GSEC_OK) {
    return result;
  }
  return x509_sig_bits(out->sig_key, bits, bits_len, &out->sig, &out->sig_len,
      out->ecdsa_raw);
}

GSEC_Result gsec_crl_signed_by(const GSEC_Crl * crl, const GSEC_X509 * issuer) {
  if (crl == NULL || crl->tbs == NULL) {
    return GSEC_ERR_INVALID;
  }
  return x509_sig_verify(crl->sig_key, crl->sig_hash, crl->sig, crl->sig_len,
      crl->tbs, crl->tbs_len, issuer);
}

GSEC_Result gsec_crl_contains(const GSEC_Crl * crl, const void * serial,
    size_t serial_len) {
  const unsigned char * p;
  size_t left;

  if (crl == NULL || (serial == NULL && serial_len != 0)) {
    return GSEC_ERR_INVALID;
  }
  p = crl->revoked;
  left = crl->revoked_len;
  while (left != 0) {
    GSEC_Der entry;
    GSEC_Der num;
    const unsigned char * ep;
    size_t eleft;
    const unsigned char * be;
    size_t be_len;
    GSEC_Result result = gsec_der_next(&p, &left, &entry);
    if (result != GSEC_OK || !gsec_der_is(&entry, GSEC_DER_UNIVERSAL, 1, 16)) {
      return GSEC_ERR_CORRUPT;
    }
    ep = entry.value;
    eleft = entry.value_len;
    result = gsec_der_next(&ep, &eleft, &num);
    if (result != GSEC_OK) {
      return result;
    }
    result = gsec_der_unsigned(&num, &be, &be_len);
    if (result != GSEC_OK) {
      return result;
    }
    if (same_uint(be, be_len, serial, serial_len)) {
      return GSEC_OK;
    }
  }
  return GSEC_ERR_MISMATCH;
}
