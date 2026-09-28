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
 * PBES1 and the PKCS#12 password-based encryption schemes. PBES2 stays in
 * pbes2.c. A PKCS#12 scheme turns the password into UTF-16BE here. PBES1
 * uses the password bytes as given.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/des.h>
#include <ghoti.io/security/hmac.h>
#include <ghoti.io/security/md5.h>
#include <ghoti.io/security/rc2.h>
#include <ghoti.io/security/rc4.h>
#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/sha1.h>

#include "../der/der_int.h"
#include "pbes2.h"

#include <string.h>

#define CT_MAX 65536u
#define SALT_MAX 128u
#define BMP_MAX 514u

static const unsigned char OID_PBES2[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d
};
static const unsigned char OID_MD5_DES[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x03
};
static const unsigned char OID_MD5_RC2[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x06
};
static const unsigned char OID_SHA1_DES[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0a
};
static const unsigned char OID_SHA1_RC2[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0b
};
static const unsigned char OID_P12_RC4_128[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x01
};
static const unsigned char OID_P12_RC4_40[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x02
};
static const unsigned char OID_P12_3DES[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03
};
static const unsigned char OID_P12_2DES[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x04
};
static const unsigned char OID_P12_RC2_128[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x05
};
static const unsigned char OID_P12_RC2_40[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x06
};

enum {
  KIND_PBES2 = 0,
  KIND_MD5,
  KIND_SHA1,
  KIND_P12
};

enum {
  CIPHER_DES = 1,
  CIPHER_RC2,
  CIPHER_EDE3,
  CIPHER_EDE2,
  CIPHER_RC4
};

typedef struct Scheme {
  const unsigned char * oid;
  size_t oid_len;
  int kind;
  int cipher;
  size_t key_len;
  uint32_t effective;
} Scheme;

static const Scheme SCHEMES[] = {
  {OID_PBES2, sizeof OID_PBES2, KIND_PBES2, 0, 0, 0},
  {OID_MD5_DES, sizeof OID_MD5_DES, KIND_MD5, CIPHER_DES, 8, 0},
  {OID_MD5_RC2, sizeof OID_MD5_RC2, KIND_MD5, CIPHER_RC2, 8, 64},
  {OID_SHA1_DES, sizeof OID_SHA1_DES, KIND_SHA1, CIPHER_DES, 8, 0},
  {OID_SHA1_RC2, sizeof OID_SHA1_RC2, KIND_SHA1, CIPHER_RC2, 8, 64},
  {OID_P12_RC4_128, sizeof OID_P12_RC4_128, KIND_P12, CIPHER_RC4, 16, 0},
  {OID_P12_RC4_40, sizeof OID_P12_RC4_40, KIND_P12, CIPHER_RC4, 5, 0},
  {OID_P12_3DES, sizeof OID_P12_3DES, KIND_P12, CIPHER_EDE3, 24, 0},
  {OID_P12_2DES, sizeof OID_P12_2DES, KIND_P12, CIPHER_EDE2, 16, 0},
  {OID_P12_RC2_128, sizeof OID_P12_RC2_128, KIND_P12, CIPHER_RC2, 16, 128},
  {OID_P12_RC2_40, sizeof OID_P12_RC2_40, KIND_P12, CIPHER_RC2, 5, 40},
};

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

static GSEC_Result hash_once(int sha1, const unsigned char * a, size_t an,
    const unsigned char * b, size_t bn, unsigned char * out) {
  GSEC_Result result;

  if (sha1) {
    GSEC_Sha1 ctx;

    result = gsec_sha1_init(&ctx);
    if (result != GSEC_OK) {
      return result;
    }
    if (an != 0) {
      result = gsec_sha1_update(&ctx, a, an);
    }
    if (result == GSEC_OK && bn != 0) {
      result = gsec_sha1_update(&ctx, b, bn);
    }
    if (result != GSEC_OK) {
      gsec_wipe(&ctx, sizeof ctx);
      return result;
    }
    return gsec_sha1_final(&ctx, out);
  }
  {
    GSEC_Md5 ctx;

    result = gsec_md5_init(&ctx);
    if (result != GSEC_OK) {
      return result;
    }
    if (an != 0) {
      result = gsec_md5_update(&ctx, a, an);
    }
    if (result == GSEC_OK && bn != 0) {
      result = gsec_md5_update(&ctx, b, bn);
    }
    if (result != GSEC_OK) {
      gsec_wipe(&ctx, sizeof ctx);
      return result;
    }
    return gsec_md5_final(&ctx, out);
  }
}

static GSEC_Result pbkdf1(int sha1, const void * password, size_t password_len,
    const unsigned char * salt, size_t salt_len, uint32_t iterations,
    unsigned char derived[16]) {
  unsigned char digest[GSEC_SHA1_DIGEST_LEN];
  size_t digest_len = sha1 ? GSEC_SHA1_DIGEST_LEN : GSEC_MD5_DIGEST_LEN;
  uint32_t i;
  GSEC_Result result;

  result = hash_once(sha1, password, password_len, salt, salt_len, digest);
  if (result != GSEC_OK) {
    return result;
  }
  for (i = 1; i < iterations; i++) {
    if (sha1) {
      result = gsec_sha1(digest, digest_len, digest);
    } else {
      result = gsec_md5(digest, digest_len, digest);
    }
    if (result != GSEC_OK) {
      gsec_wipe(digest, sizeof digest);
      return result;
    }
  }
  memcpy(derived, digest, 16);
  gsec_wipe(digest, sizeof digest);
  return GSEC_OK;
}

static GSEC_Result apply_cipher(const Scheme * scheme, const unsigned char * key,
    const unsigned char * iv, const void * ct, size_t ct_len, void * out,
    size_t * out_len) {
  GSEC_Result result;
  size_t block = 8;

  if (scheme->cipher == CIPHER_RC4) {
    result = gsec_rc4(key, scheme->key_len, ct, ct_len, out);
    if (result != GSEC_OK) {
      return result;
    }
    *out_len = ct_len;
    return GSEC_OK;
  }
  if (scheme->cipher == CIPHER_DES) {
    result = gsec_des_cbc_decrypt(key, iv, ct, ct_len, out);
  } else if (scheme->cipher == CIPHER_EDE3) {
    result = gsec_des_ede3_cbc_decrypt(key, iv, ct, ct_len, out);
  } else if (scheme->cipher == CIPHER_EDE2) {
    result = gsec_des_ede2_cbc_decrypt(key, iv, ct, ct_len, out);
  } else {
    result = gsec_rc2_cbc_decrypt(key, scheme->key_len, scheme->effective, iv,
        ct, ct_len, out);
  }
  if (result != GSEC_OK) {
    return result;
  }
  return gsec_pkcs7_unpad(out, ct_len, block, out_len);
}

static GSEC_Result legacy_decrypt(const Scheme * scheme, const GSEC_Der * params,
    const void * ct, size_t ct_len, const void * password, size_t password_len,
    void * out, size_t out_cap, size_t * out_len) {
  const unsigned char * p;
  size_t left;
  GSEC_Der salt;
  GSEC_Der count;
  uint32_t iterations = 0;
  unsigned char derived[16];
  unsigned char key[24];
  unsigned char iv[8];
  unsigned char bmp[BMP_MAX];
  size_t bmp_len = 0;
  const unsigned char * pass;
  size_t pass_len;
  size_t block = scheme->cipher == CIPHER_RC4 ? 1u : 8u;
  GSEC_Result result;

  if (!gsec_der_is(params, GSEC_DER_UNIVERSAL, 1, 16)) {
    return GSEC_ERR_CORRUPT;
  }
  p = params->value;
  left = params->value_len;
  result = gsec_der_next(&p, &left, &salt);
  if (result != GSEC_OK || !gsec_der_is(&salt, GSEC_DER_UNIVERSAL, 0, 4) ||
      salt.value_len > SALT_MAX) {
    return result != GSEC_OK ? result : GSEC_ERR_CORRUPT;
  }
  result = gsec_der_next(&p, &left, &count);
  if (result != GSEC_OK || left != 0) {
    return GSEC_ERR_CORRUPT;
  }
  result = u32_of(&count, &iterations);
  if (result != GSEC_OK) {
    return result;
  }
  if (iterations == 0) {
    return GSEC_ERR_INVALID;
  }
  if (iterations > GSEC_PBES2_ITER_MAX) {
    return GSEC_ERR_LIMIT;
  }
  if (ct_len == 0 || ct_len > CT_MAX || ct_len > out_cap ||
      (ct_len % block) != 0) {
    return ct_len > out_cap || ct_len > CT_MAX ? GSEC_ERR_LIMIT
        : GSEC_ERR_CORRUPT;
  }
  if (scheme->kind == KIND_P12) {
    result = gsec_pkcs12_bmp(password, password_len, bmp, &bmp_len);
    if (result != GSEC_OK) {
      return result;
    }
    pass = bmp;
    pass_len = bmp_len;
    result = gsec_pkcs12_kdf(GSEC_HMAC_SHA1, GSEC_SHA1_DIGEST_LEN, 64, pass,
        pass_len, salt.value, salt.value_len, iterations, 1, key,
        scheme->key_len);
    if (result == GSEC_OK && scheme->cipher != CIPHER_RC4) {
      result = gsec_pkcs12_kdf(GSEC_HMAC_SHA1, GSEC_SHA1_DIGEST_LEN, 64, pass,
          pass_len, salt.value, salt.value_len, iterations, 2, iv, sizeof iv);
    }
  } else {
    pass = password;
    pass_len = password_len;
    result = pbkdf1(scheme->kind == KIND_SHA1, pass, pass_len, salt.value,
        salt.value_len, iterations, derived);
    if (result == GSEC_OK) {
      memcpy(key, derived, 8);
      memcpy(iv, derived + 8, 8);
    }
  }
  gsec_wipe(bmp, sizeof bmp);
  gsec_wipe(derived, sizeof derived);
  if (result != GSEC_OK) {
    gsec_wipe(key, sizeof key);
    gsec_wipe(iv, sizeof iv);
    return result;
  }
  result = apply_cipher(scheme, key, iv, ct, ct_len, out, out_len);
  gsec_wipe(key, sizeof key);
  gsec_wipe(iv, sizeof iv);
  if (result != GSEC_OK) {
    gsec_wipe(out, ct_len);
  }
  return result;
}

GSEC_Result gsec_pbe_decrypt(const GSEC_Der * alg, const void * ct,
    size_t ct_len, const void * password, size_t password_len, void * out,
    size_t out_cap, size_t * out_len) {
  const unsigned char * p;
  size_t left;
  GSEC_Der oid;
  GSEC_Der params;
  GSEC_Result result;
  size_t i;

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
  for (i = 0; i < sizeof SCHEMES / sizeof SCHEMES[0]; i++) {
    if (gsec_der_oid_is(&oid, SCHEMES[i].oid, SCHEMES[i].oid_len)) {
      if (SCHEMES[i].kind == KIND_PBES2) {
        return gsec_pbes2_decrypt(alg, ct, ct_len, password, password_len, out,
            out_cap, out_len);
      }
      result = gsec_der_next(&p, &left, &params);
      if (result != GSEC_OK || left != 0) {
        return GSEC_ERR_CORRUPT;
      }
      return legacy_decrypt(&SCHEMES[i], &params, ct, ct_len, password,
          password_len, out, out_cap, out_len);
    }
  }
  return GSEC_ERR_UNSUPPORTED;
}
