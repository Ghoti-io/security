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
 * PBES2 with PBKDF2 and AES-CBC or three-key Triple DES. The padding
 * check walks the whole last block and only then branches.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/aes_cbc.h>
#include <ghoti.io/security/des.h>
#include <ghoti.io/security/pbkdf2.h>
#include <ghoti.io/security/secret.h>

#include "../der/der_int.h"
#include "pbes2.h"

#include <string.h>

#if defined(GSEC_CT_TEST)
#include <valgrind/memcheck.h>
#endif

static const unsigned char OID_PBES2[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d
};
static const unsigned char OID_PBKDF2[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c
};
static const unsigned char OID_HMAC_SHA1[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07
};
static const unsigned char OID_HMAC_SHA256[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09
};
static const unsigned char OID_HMAC_SHA384[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a
};
static const unsigned char OID_HMAC_SHA512[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b
};
static const unsigned char OID_AES128[] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02
};
static const unsigned char OID_AES192[] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16
};
static const unsigned char OID_AES256[] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a
};
static const unsigned char OID_DES_EDE3[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07
};

static uint32_t bit_of(uint32_t x) {
  x |= x >> 16;
  x |= x >> 8;
  x |= x >> 4;
  x |= x >> 2;
  x |= x >> 1;
  return x & 1u;
}

static uint32_t eq_byte(unsigned char a, uint32_t b) {
  return bit_of((uint32_t)a ^ b) ^ 1u;
}

static GSEC_Result u32_of(const GSEC_Der * v, uint32_t * out) {
  const unsigned char * be;
  size_t n;
  size_t i;
  uint32_t value;
  GSEC_Result result;

  result = gsec_der_unsigned(v, &be, &n);
  if (result != GSEC_OK) {
    return result;
  }
  if (n == 0 || n > 4) {
    return GSEC_ERR_LIMIT;
  }
  value = 0;
  for (i = 0; i < n; i++) {
    value = (value << 8) | be[i];
  }
  *out = value;
  return GSEC_OK;
}

static GSEC_Result prf_of(const GSEC_Der * alg, uint32_t * hash) {
  const unsigned char * p;
  size_t left;
  GSEC_Der oid;
  GSEC_Result result;

  if (alg == NULL) {
    *hash = GSEC_PBKDF2_SHA1;
    return GSEC_OK;
  }
  if (!gsec_der_is(alg, GSEC_DER_UNIVERSAL, 1, 16)) {
    return GSEC_ERR_CORRUPT;
  }
  p = alg->value;
  left = alg->value_len;
  result = gsec_der_next(&p, &left, &oid);
  if (result != GSEC_OK || gsec_der_oid_ok(&oid) != GSEC_OK) {
    return GSEC_ERR_CORRUPT;
  }
  if (gsec_der_oid_is(&oid, OID_HMAC_SHA1, sizeof OID_HMAC_SHA1)) {
    *hash = GSEC_PBKDF2_SHA1;
  } else if (gsec_der_oid_is(&oid, OID_HMAC_SHA256, sizeof OID_HMAC_SHA256)) {
    *hash = GSEC_PBKDF2_SHA256;
  } else if (gsec_der_oid_is(&oid, OID_HMAC_SHA384, sizeof OID_HMAC_SHA384)) {
    *hash = GSEC_PBKDF2_SHA384;
  } else if (gsec_der_oid_is(&oid, OID_HMAC_SHA512, sizeof OID_HMAC_SHA512)) {
    *hash = GSEC_PBKDF2_SHA512;
  } else {
    return GSEC_ERR_UNSUPPORTED;
  }
  if (left != 0) {
    GSEC_Der param;
    result = gsec_der_next(&p, &left, &param);
    if (result != GSEC_OK || left != 0) {
      return GSEC_ERR_CORRUPT;
    }
    if (!gsec_der_is(&param, GSEC_DER_UNIVERSAL, 0, 5) || param.value_len != 0) {
      return GSEC_ERR_UNSUPPORTED;
    }
  }
  return GSEC_OK;
}

GSEC_Result gsec_pkcs7_unpad(unsigned char * buf, size_t n, size_t block,
    size_t * out_len) {
  const volatile unsigned char * secret;
  uint32_t pad;
  uint32_t ok;
  size_t i;

  if (n == 0 || block == 0 || (n % block) != 0) {
    return GSEC_ERR_CORRUPT;
  }
  secret = buf;
  pad = secret[n - 1u];
  ok = ((pad - 1u) >> 31) ^ 1u;
  ok &= (((uint32_t)block - pad) >> 31) ^ 1u;
  for (i = 0; i < n; i++) {
    uint32_t from = (uint32_t)n - pad;
    uint32_t in_pad = (((uint32_t)i - from) >> 31) ^ 1u;
    uint32_t same = eq_byte(secret[i], pad);

    ok &= (in_pad ^ 1u) | same;
  }
#if defined(GSEC_CT_TEST)
  VALGRIND_MAKE_MEM_DEFINED(&ok, sizeof ok);
  VALGRIND_MAKE_MEM_DEFINED(&pad, sizeof pad);
  VALGRIND_MAKE_MEM_DEFINED(buf, n);
#endif
  if (ok == 0) {
    gsec_wipe(buf, n);
    return GSEC_ERR_MISMATCH;
  }
  *out_len = n - pad;
  gsec_wipe(buf + *out_len, pad);
  return GSEC_OK;
}

GSEC_Result gsec_pbes2_decrypt(uint32_t iter_max, const GSEC_Der * alg,
    const void * ct,
    size_t ct_len, const void * password, size_t password_len, void * out,
    size_t out_cap, size_t * out_len) {
  const unsigned char * p;
  size_t left;
  GSEC_Der oid;
  GSEC_Der params;
  GSEC_Der kdf;
  GSEC_Der enc;
  GSEC_Der field;
  GSEC_Result result;
  const unsigned char * salt = NULL;
  size_t salt_len = 0;
  const unsigned char * iv = NULL;
  size_t iv_len = 0;
  uint32_t iterations = 0;
  uint32_t hash = GSEC_PBKDF2_SHA1;
  uint32_t key_len = 0;
  int key_len_set = 0;
  size_t block = 0;
  unsigned char key[32];
  int triple = 0;

  if (alg == NULL || out_len == NULL || (ct == NULL && ct_len != 0) ||
      (password == NULL && password_len != 0) || out == NULL) {
    return GSEC_ERR_INVALID;
  }
  if (!gsec_der_is(alg, GSEC_DER_UNIVERSAL, 1, 16)) {
    return GSEC_ERR_CORRUPT;
  }
  p = alg->value;
  left = alg->value_len;
  result = gsec_der_next(&p, &left, &oid);
  if (result != GSEC_OK || gsec_der_oid_ok(&oid) != GSEC_OK) {
    return result != GSEC_OK ? result : GSEC_ERR_CORRUPT;
  }
  if (!gsec_der_oid_is(&oid, OID_PBES2, sizeof OID_PBES2)) {
    return GSEC_ERR_UNSUPPORTED;
  }
  result = gsec_der_next(&p, &left, &params);
  if (result != GSEC_OK || left != 0 ||
      !gsec_der_is(&params, GSEC_DER_UNIVERSAL, 1, 16)) {
    return GSEC_ERR_CORRUPT;
  }
  p = params.value;
  left = params.value_len;
  result = gsec_der_next(&p, &left, &kdf);
  if (result != GSEC_OK || !gsec_der_is(&kdf, GSEC_DER_UNIVERSAL, 1, 16)) {
    return GSEC_ERR_CORRUPT;
  }
  result = gsec_der_next(&p, &left, &enc);
  if (result != GSEC_OK || left != 0 ||
      !gsec_der_is(&enc, GSEC_DER_UNIVERSAL, 1, 16)) {
    return GSEC_ERR_CORRUPT;
  }
  p = kdf.value;
  left = kdf.value_len;
  result = gsec_der_next(&p, &left, &oid);
  if (result != GSEC_OK || !gsec_der_oid_is(&oid, OID_PBKDF2, sizeof OID_PBKDF2)) {
    return result != GSEC_OK ? result : GSEC_ERR_UNSUPPORTED;
  }
  result = gsec_der_next(&p, &left, &params);
  if (result != GSEC_OK || left != 0 ||
      !gsec_der_is(&params, GSEC_DER_UNIVERSAL, 1, 16)) {
    return GSEC_ERR_CORRUPT;
  }
  p = params.value;
  left = params.value_len;
  result = gsec_der_next(&p, &left, &field);
  if (result != GSEC_OK) {
    return result;
  }
  if (!gsec_der_is(&field, GSEC_DER_UNIVERSAL, 0, 4)) {
    return GSEC_ERR_UNSUPPORTED;
  }
  salt = field.value;
  salt_len = field.value_len;
  result = gsec_der_next(&p, &left, &field);
  if (result != GSEC_OK) {
    return result;
  }
  result = u32_of(&field, &iterations);
  if (result != GSEC_OK) {
    return result;
  }
  if (iterations == 0 || iterations > iter_max) {
    return iterations == 0 ? GSEC_ERR_INVALID : GSEC_ERR_LIMIT;
  }
  if (left != 0) {
    result = gsec_der_next(&p, &left, &field);
    if (result != GSEC_OK) {
      return result;
    }
    if (gsec_der_is(&field, GSEC_DER_UNIVERSAL, 0, 2)) {
      result = u32_of(&field, &key_len);
      if (result != GSEC_OK) {
        return result;
      }
      key_len_set = 1;
      if (left != 0) {
        result = gsec_der_next(&p, &left, &field);
        if (result != GSEC_OK || left != 0) {
          return GSEC_ERR_CORRUPT;
        }
        result = prf_of(&field, &hash);
      }
    } else {
      result = prf_of(&field, &hash);
    }
    if (result != GSEC_OK) {
      return result;
    }
  }
  p = enc.value;
  left = enc.value_len;
  result = gsec_der_next(&p, &left, &oid);
  if (result != GSEC_OK || gsec_der_oid_ok(&oid) != GSEC_OK) {
    return result != GSEC_OK ? result : GSEC_ERR_CORRUPT;
  }
  if (gsec_der_oid_is(&oid, OID_AES128, sizeof OID_AES128)) {
    key_len = key_len_set ? key_len : 16u;
    block = GSEC_AES_BLOCK_LEN;
  } else if (gsec_der_oid_is(&oid, OID_AES192, sizeof OID_AES192)) {
    key_len = key_len_set ? key_len : 24u;
    block = GSEC_AES_BLOCK_LEN;
  } else if (gsec_der_oid_is(&oid, OID_AES256, sizeof OID_AES256)) {
    key_len = key_len_set ? key_len : 32u;
    block = GSEC_AES_BLOCK_LEN;
  } else if (gsec_der_oid_is(&oid, OID_DES_EDE3, sizeof OID_DES_EDE3)) {
    key_len = key_len_set ? key_len : 24u;
    block = GSEC_DES_BLOCK_LEN;
    triple = 1;
  } else {
    return GSEC_ERR_UNSUPPORTED;
  }
  if ((triple && key_len != 24u) ||
      (!triple && key_len != 16u && key_len != 24u && key_len != 32u)) {
    return GSEC_ERR_UNSUPPORTED;
  }
  result = gsec_der_next(&p, &left, &field);
  if (result != GSEC_OK || left != 0 ||
      !gsec_der_is(&field, GSEC_DER_UNIVERSAL, 0, 4) ||
      field.value_len != block) {
    return GSEC_ERR_CORRUPT;
  }
  iv = field.value;
  iv_len = field.value_len;
  if (ct_len == 0 || (ct_len % block) != 0 || ct_len > out_cap ||
      ct_len > 65536u) {
    return ct_len > out_cap || ct_len > 65536u ? GSEC_ERR_LIMIT
        : GSEC_ERR_CORRUPT;
  }
  result = gsec_pbkdf2(hash, password, password_len, salt, salt_len, iterations,
      key, key_len);
  if (result != GSEC_OK) {
    gsec_wipe(key, sizeof key);
    return result;
  }
  if (triple) {
    result = gsec_des_ede3_cbc_decrypt(key, iv, ct, ct_len, out);
  } else {
    result = gsec_aes_cbc_decrypt(key, key_len, iv, ct, ct_len, out);
  }
  gsec_wipe(key, sizeof key);
  (void)iv_len;
  if (result != GSEC_OK) {
    gsec_wipe(out, ct_len);
    return result;
  }
  return gsec_pkcs7_unpad(out, ct_len, block, out_len);
}
