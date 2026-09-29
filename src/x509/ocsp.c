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
 * BasicOCSPResponse. The single responses stay in the caller's buffer.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/hmac.h>
#include <ghoti.io/security/ocsp.h>

#include "../der/der_int.h"
#include "signed.h"

#include <string.h>

static const unsigned char OID_BASIC[] = {
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01
};
static const unsigned char OID_SHA1[] = {0x2b, 0x0e, 0x03, 0x02, 0x1a};
static const unsigned char OID_SHA256[] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
};
static const unsigned char OID_SHA384[] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
};
static const unsigned char OID_SHA512[] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
};
static const unsigned char OID_NONCE[] = {
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02
};

static int known_ext(const GSEC_Der * oid) {
  return gsec_der_oid_is(oid, OID_NONCE, sizeof OID_NONCE);
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
    int critical = 0;
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
      if (field.value_len != 1 || (field.value[0] != 0 && field.value[0] != 0xff)) {
        return GSEC_ERR_CORRUPT;
      }
      critical = field.value[0] == 0xff;
      result = gsec_der_next(&ep, &eleft, &field);
      if (result != GSEC_OK) {
        return result;
      }
    }
    if (eleft != 0 || !gsec_der_is(&field, GSEC_DER_UNIVERSAL, 0, 4)) {
      return GSEC_ERR_CORRUPT;
    }
    if (critical && !known_ext(&oid)) {
      return GSEC_ERR_UNSUPPORTED;
    }
  }
  return GSEC_OK;
}

static int hash_of(const GSEC_Der * alg, uint32_t * hash, size_t * dig) {
  const unsigned char * p;
  size_t left;
  GSEC_Der oid;
  GSEC_Der param;

  if (!gsec_der_is(alg, GSEC_DER_UNIVERSAL, 1, 16)) {
    return 0;
  }
  p = alg->value;
  left = alg->value_len;
  if (gsec_der_next(&p, &left, &oid) != GSEC_OK || gsec_der_oid_ok(&oid) != GSEC_OK) {
    return 0;
  }
  if (left != 0) {
    if (gsec_der_next(&p, &left, &param) != GSEC_OK || left != 0 ||
        !gsec_der_is(&param, GSEC_DER_UNIVERSAL, 0, 5) || param.value_len != 0) {
      return 0;
    }
  }
  if (gsec_der_oid_is(&oid, OID_SHA1, sizeof OID_SHA1)) {
    *hash = GSEC_HMAC_SHA1;
    *dig = 20;
  } else if (gsec_der_oid_is(&oid, OID_SHA256, sizeof OID_SHA256)) {
    *hash = GSEC_HMAC_SHA256;
    *dig = 32;
  } else if (gsec_der_oid_is(&oid, OID_SHA384, sizeof OID_SHA384)) {
    *hash = GSEC_HMAC_SHA384;
    *dig = 48;
  } else if (gsec_der_oid_is(&oid, OID_SHA512, sizeof OID_SHA512)) {
    *hash = GSEC_HMAC_SHA512;
    *dig = 64;
  } else {
    return 0;
  }
  return 1;
}

GSEC_Result gsec_ocsp_parse(const void * der, size_t len, GSEC_Ocsp * out) {
  GSEC_Der seq;
  GSEC_Der status;
  GSEC_Der bytes;
  GSEC_Der basic_wrap;
  GSEC_Der oid;
  GSEC_Der oct;
  GSEC_Der basic;
  GSEC_Der tbs;
  GSEC_Der alg;
  GSEC_Der sig;
  GSEC_Der field;
  GSEC_Result result;
  const unsigned char * p;
  size_t left;
  const unsigned char * bits;
  size_t bits_len;
  const unsigned char * be;
  size_t be_len;

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
  result = gsec_der_next(&p, &left, &status);
  if (result != GSEC_OK || !gsec_der_is(&status, GSEC_DER_UNIVERSAL, 0, 10)) {
    return GSEC_ERR_CORRUPT;
  }
  if (status.value_len != 1 || status.value[0] != 0) {
    return GSEC_ERR_UNSUPPORTED;
  }
  result = gsec_der_next(&p, &left, &bytes);
  if (result != GSEC_OK || left != 0 || bytes.tag_class != GSEC_DER_CONTEXT ||
      bytes.constructed != 1 || bytes.number != 0) {
    return GSEC_ERR_CORRUPT;
  }
  result = gsec_der_tlv(bytes.value, bytes.value_len, &basic_wrap);
  if (result != GSEC_OK || basic_wrap.total_len != bytes.value_len ||
      !gsec_der_is(&basic_wrap, GSEC_DER_UNIVERSAL, 1, 16)) {
    return GSEC_ERR_CORRUPT;
  }
  p = basic_wrap.value;
  left = basic_wrap.value_len;
  result = gsec_der_next(&p, &left, &oid);
  if (result != GSEC_OK || gsec_der_oid_ok(&oid) != GSEC_OK) {
    return GSEC_ERR_CORRUPT;
  }
  if (!gsec_der_oid_is(&oid, OID_BASIC, sizeof OID_BASIC)) {
    return GSEC_ERR_UNSUPPORTED;
  }
  result = gsec_der_next(&p, &left, &oct);
  if (result != GSEC_OK || left != 0 ||
      !gsec_der_is(&oct, GSEC_DER_UNIVERSAL, 0, 4)) {
    return GSEC_ERR_CORRUPT;
  }
  result = gsec_der_tlv(oct.value, oct.value_len, &basic);
  if (result != GSEC_OK || basic.total_len != oct.value_len ||
      !gsec_der_is(&basic, GSEC_DER_UNIVERSAL, 1, 16)) {
    return GSEC_ERR_CORRUPT;
  }
  p = basic.value;
  left = basic.value_len;
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
  if (result != GSEC_OK) {
    return result;
  }
  if (left != 0) {
    GSEC_Der certs;
    GSEC_Der one;
    result = gsec_der_next(&p, &left, &certs);
    if (result != GSEC_OK || left != 0 || certs.tag_class != GSEC_DER_CONTEXT ||
        certs.constructed != 1 || certs.number != 0) {
      return GSEC_ERR_CORRUPT;
    }
    result = gsec_der_tlv(certs.value, certs.value_len, &one);
    if (result != GSEC_OK || one.total_len != certs.value_len ||
        !gsec_der_is(&one, GSEC_DER_UNIVERSAL, 1, 16)) {
      return GSEC_ERR_CORRUPT;
    }
  }
  result = x509_sig_alg(&alg, &out->sig_key, &out->sig_hash);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_der_bit_payload(&sig, &bits, &bits_len);
  if (result != GSEC_OK) {
    return result;
  }
  result = x509_sig_bits(out->sig_key, bits, bits_len, &out->sig, &out->sig_len,
      out->ecdsa_raw);
  if (result != GSEC_OK) {
    return result;
  }
  p = tbs.value;
  left = tbs.value_len;
  result = gsec_der_next(&p, &left, &field);
  if (result != GSEC_OK) {
    return result;
  }
  if (field.tag_class == GSEC_DER_CONTEXT && field.constructed == 1 &&
      field.number == 0) {
    GSEC_Der ver;
    result = gsec_der_tlv(field.value, field.value_len, &ver);
    if (result != GSEC_OK || ver.total_len != field.value_len) {
      return GSEC_ERR_CORRUPT;
    }
    result = gsec_der_unsigned(&ver, &be, &be_len);
    if (result != GSEC_OK || be_len != 1 || be[0] != 0) {
      return GSEC_ERR_CORRUPT;
    }
    result = gsec_der_next(&p, &left, &field);
    if (result != GSEC_OK) {
      return result;
    }
  }
  if (!(field.tag_class == GSEC_DER_CONTEXT && field.constructed == 1 &&
      (field.number == 1 || field.number == 2))) {
    return GSEC_ERR_CORRUPT;
  }
  result = gsec_der_next(&p, &left, &field);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_der_time(&field, &out->produced_at);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_der_next(&p, &left, &field);
  if (result != GSEC_OK || !gsec_der_is(&field, GSEC_DER_UNIVERSAL, 1, 16)) {
    return GSEC_ERR_CORRUPT;
  }
  out->responses = field.value;
  out->responses_len = field.value_len;
  if (left != 0) {
    result = gsec_der_next(&p, &left, &field);
    if (result != GSEC_OK || left != 0 || field.tag_class != GSEC_DER_CONTEXT ||
        field.constructed != 1 || field.number != 1) {
      return GSEC_ERR_CORRUPT;
    }
    result = skip_extensions(field.value, field.value_len);
    if (result != GSEC_OK) {
      return result;
    }
  }
  return GSEC_OK;
}

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

GSEC_Result gsec_ocsp_signed_by(const GSEC_Ocsp * ocsp, const GSEC_X509 * issuer) {
  if (ocsp == NULL || ocsp->tbs == NULL) {
    return GSEC_ERR_INVALID;
  }
  return x509_sig_verify(ocsp->sig_key, ocsp->sig_hash, ocsp->sig, ocsp->sig_len,
      ocsp->tbs, ocsp->tbs_len, issuer);
}

GSEC_Result gsec_ocsp_status(const GSEC_Ocsp * ocsp, uint32_t hash,
    const void * name_hash, size_t name_hash_len, const void * key_hash,
    size_t key_hash_len, const void * serial, size_t serial_len,
    GSEC_Ocsp_Single * out) {
  const unsigned char * p;
  size_t left;
  size_t expect;

  if (ocsp == NULL || out == NULL || (name_hash == NULL && name_hash_len != 0) ||
      (key_hash == NULL && key_hash_len != 0) || (serial == NULL && serial_len != 0)) {
    return GSEC_ERR_INVALID;
  }
  out->status = GSEC_OCSP_UNKNOWN;
  out->this_update = 0;
  out->next_update = 0;
  out->have_next_update = 0;
  out->revoked_at = 0;
  if (hash == GSEC_HMAC_SHA1) {
    expect = 20;
  } else if (hash == GSEC_HMAC_SHA256) {
    expect = 32;
  } else if (hash == GSEC_HMAC_SHA384) {
    expect = 48;
  } else if (hash == GSEC_HMAC_SHA512) {
    expect = 64;
  } else {
    return GSEC_ERR_INVALID;
  }
  if (name_hash_len != expect || key_hash_len != expect) {
    return GSEC_ERR_INVALID;
  }
  p = ocsp->responses;
  left = ocsp->responses_len;
  while (left != 0) {
    GSEC_Der one;
    GSEC_Der cert_id;
    GSEC_Der alg;
    GSEC_Der name;
    GSEC_Der key;
    GSEC_Der num;
    GSEC_Der st;
    const unsigned char * ep;
    size_t eleft;
    const unsigned char * be;
    size_t be_len;
    uint32_t got_hash;
    size_t dig;
    GSEC_Result result = gsec_der_next(&p, &left, &one);
    if (result != GSEC_OK || !gsec_der_is(&one, GSEC_DER_UNIVERSAL, 1, 16)) {
      return GSEC_ERR_CORRUPT;
    }
    ep = one.value;
    eleft = one.value_len;
    result = gsec_der_next(&ep, &eleft, &cert_id);
    if (result != GSEC_OK || !gsec_der_is(&cert_id, GSEC_DER_UNIVERSAL, 1, 16)) {
      return GSEC_ERR_CORRUPT;
    }
    {
      const unsigned char * cp = cert_id.value;
      size_t cleft = cert_id.value_len;
      result = gsec_der_next(&cp, &cleft, &alg);
      if (result != GSEC_OK) {
        return result;
      }
      result = gsec_der_next(&cp, &cleft, &name);
      if (result != GSEC_OK || !gsec_der_is(&name, GSEC_DER_UNIVERSAL, 0, 4)) {
        return GSEC_ERR_CORRUPT;
      }
      result = gsec_der_next(&cp, &cleft, &key);
      if (result != GSEC_OK || cleft == 0 ||
          !gsec_der_is(&key, GSEC_DER_UNIVERSAL, 0, 4)) {
        return GSEC_ERR_CORRUPT;
      }
      result = gsec_der_next(&cp, &cleft, &num);
      if (result != GSEC_OK || cleft != 0) {
        return GSEC_ERR_CORRUPT;
      }
    }
    if (!hash_of(&alg, &got_hash, &dig) || got_hash != hash) {
      continue;
    }
    result = gsec_der_unsigned(&num, &be, &be_len);
    if (result != GSEC_OK) {
      return result;
    }
    if (name.value_len != name_hash_len || key.value_len != key_hash_len ||
        !gsec_der_eq(name.value, name.value_len, name_hash, name_hash_len) ||
        !gsec_der_eq(key.value, key.value_len, key_hash, key_hash_len) ||
        !same_uint(be, be_len, serial, serial_len)) {
      continue;
    }
    result = gsec_der_next(&ep, &eleft, &st);
    if (result != GSEC_OK || st.tag_class != GSEC_DER_CONTEXT) {
      return GSEC_ERR_CORRUPT;
    }
    if (st.number == 0 && st.value_len == 0) {
      out->status = GSEC_OCSP_GOOD;
    } else if (st.number == 2 && st.value_len == 0) {
      out->status = GSEC_OCSP_UNKNOWN;
    } else if (st.number == 1 && st.constructed == 1) {
      GSEC_Der when;
      const unsigned char * rp = st.value;
      size_t rleft = st.value_len;
      out->status = GSEC_OCSP_REVOKED;
      result = gsec_der_next(&rp, &rleft, &when);
      if (result != GSEC_OK) {
        return result;
      }
      result = gsec_der_time(&when, &out->revoked_at);
      if (result != GSEC_OK) {
        return result;
      }
    } else {
      return GSEC_ERR_CORRUPT;
    }
    /* thisUpdate, then nextUpdate if it is there. RFC 6960's SingleResponse
     * puts both after certStatus, and they were parsed past and dropped:
     * without them a caller has no way to tell a fresh response from one
     * replayed out of a capture. */
    result = gsec_der_next(&ep, &eleft, &st);
    if (result != GSEC_OK) {
      return result;
    }
    result = gsec_der_time(&st, &out->this_update);
    if (result != GSEC_OK) {
      return result;
    }
    if (eleft != 0) {
      result = gsec_der_next(&ep, &eleft, &st);
      if (result != GSEC_OK) {
        return result;
      }
      if (st.tag_class == GSEC_DER_CONTEXT && st.constructed == 1 &&
          st.number == 0) {
        GSEC_Der when;
        result = gsec_der_tlv(st.value, st.value_len, &when);
        if (result != GSEC_OK || when.total_len != st.value_len) {
          return GSEC_ERR_CORRUPT;
        }
        result = gsec_der_time(&when, &out->next_update);
        if (result != GSEC_OK) {
          return result;
        }
        out->have_next_update = 1;
        if (out->next_update < out->this_update) {
          return GSEC_ERR_CORRUPT;
        }
        if (eleft != 0) {
          result = gsec_der_next(&ep, &eleft, &st);
          if (result != GSEC_OK) {
            return result;
          }
        } else {
          st.tag_class = GSEC_DER_UNIVERSAL;
        }
      }
      /* singleExtensions, and a critical one this parser does not understand
       * refuses the answer rather than being ignored. skip_extensions is
       * applied to responseExtensions at parse time and was never applied
       * here, so a critical extension on the entry actually being answered was
       * read past - which is the same shape as accepting a critical
       * extendedKeyUsage and evaluating none of it.
       *
       * Only the entry being answered: a critical extension on some other
       * certificate's entry says nothing about this one, and refusing the
       * whole response for it would make an unrelated entry able to deny
       * service for this one. */
      if (st.tag_class == GSEC_DER_CONTEXT && st.constructed == 1 &&
          st.number == 1) {
        result = skip_extensions(st.value, st.value_len);
        if (result != GSEC_OK) {
          return result;
        }
      }
    }
    return GSEC_OK;
  }
  return GSEC_ERR_MISMATCH;
}
