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
 * Hash ids, DigestInfo, MGF1, and the public-key checks shared by RSA
 * verification and signing. The modulus and the public exponent are
 * public, so dropping a leading zero branches on those bytes.
 */

#include "rsa_pad.h"

#include <ghoti.io/security/md5.h>
#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/sha1.h>
#include <ghoti.io/security/sha256.h>
#include <ghoti.io/security/sha384.h>

#include <string.h>

static const unsigned char DI_MD5[] = {
  0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86,
  0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10
};
static const unsigned char DI_SHA1[] = {
  0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
  0x1a, 0x05, 0x00, 0x04, 0x14
};
static const unsigned char DI_SHA256[] = {
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
  0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};
static const unsigned char DI_SHA384[] = {
  0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
  0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
};
static const unsigned char DI_SHA512[] = {
  0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
  0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};

GSEC_Result rsa_hash_one(uint32_t id, const void * data, size_t n,
    unsigned char out[GSEC_SHA512_DIGEST_LEN], size_t * hlen,
    const unsigned char ** prefix, size_t * prefix_len) {
  GSEC_Result result;

  if (id == GSEC_RSA_MD5) {
    *hlen = GSEC_MD5_DIGEST_LEN;
    *prefix = DI_MD5;
    *prefix_len = sizeof DI_MD5;
    result = gsec_md5(data, n, out);
  } else if (id == GSEC_RSA_SHA1) {
    *hlen = GSEC_SHA1_DIGEST_LEN;
    *prefix = DI_SHA1;
    *prefix_len = sizeof DI_SHA1;
    result = gsec_sha1(data, n, out);
  } else if (id == GSEC_RSA_SHA256) {
    *hlen = GSEC_SHA256_DIGEST_LEN;
    *prefix = DI_SHA256;
    *prefix_len = sizeof DI_SHA256;
    result = gsec_sha256(data, n, out);
  } else if (id == GSEC_RSA_SHA384) {
    *hlen = GSEC_SHA384_DIGEST_LEN;
    *prefix = DI_SHA384;
    *prefix_len = sizeof DI_SHA384;
    result = gsec_sha384(data, n, out);
  } else if (id == GSEC_RSA_SHA512) {
    *hlen = GSEC_SHA512_DIGEST_LEN;
    *prefix = DI_SHA512;
    *prefix_len = sizeof DI_SHA512;
    result = gsec_sha512(data, n, out);
  } else {
    return GSEC_ERR_INVALID;
  }
  return result;
}

static void strip_zeros(const unsigned char ** p, size_t * n) {
  while (*n > 0 && (*p)[0] == 0) {
    (*p)++;
    (*n)--;
  }
}

GSEC_Result rsa_load_public(bn * mod, const unsigned char ** exp,
    size_t * exp_len, const void * n, size_t n_len, const void * e,
    size_t e_len, size_t * k) {
  const unsigned char * np = n;
  const unsigned char * ep = e;

  if (n == NULL || e == NULL || n_len == 0 || e_len == 0) {
    return GSEC_ERR_INVALID;
  }
  strip_zeros(&np, &n_len);
  strip_zeros(&ep, &e_len);
  if (n_len == 0 || e_len == 0) {
    return GSEC_ERR_INVALID;
  }
  if (n_len > GSEC_RSA_MODULUS_MAX || e_len > GSEC_RSA_MODULUS_MAX) {
    return GSEC_ERR_LIMIT;
  }
  if ((np[n_len - 1u] & 1u) == 0 || (ep[e_len - 1u] & 1u) == 0) {
    return GSEC_ERR_INVALID;
  }
  if (e_len == 1 && ep[0] < 3) {
    return GSEC_ERR_INVALID;
  }
  if (!bn_from_be(mod, np, n_len)) {
    return GSEC_ERR_LIMIT;
  }
  *exp = ep;
  *exp_len = e_len;
  *k = n_len;
  return GSEC_OK;
}

GSEC_Result rsa_mgf1(uint32_t hash, const unsigned char * seed, size_t seed_len,
    unsigned char * mask, size_t mask_len) {
  /* MODULUS_MAX, not a digest length: PSS seeds this with H, which is one
   * digest, and OAEP seeds it with DB, which is nearly the modulus. There
   * used to be a second copy of this function in rsa_crypt.c for that
   * reason, with its own bound and its own counter guard. Two MGF1s meant a
   * fix to one would not reach the other. */
  unsigned char block[GSEC_RSA_MODULUS_MAX + 4u];
  unsigned char dig[GSEC_SHA512_DIGEST_LEN];
  const unsigned char * prefix;
  size_t prefix_len;
  size_t hlen;
  size_t off;
  uint32_t counter;

  if (seed_len > GSEC_RSA_MODULUS_MAX) {
    return GSEC_ERR_INVALID;
  }
  memcpy(block, seed, seed_len);
  off = 0;
  counter = 0;
  while (off < mask_len) {
    size_t take;
    size_t i;
    GSEC_Result result;

    block[seed_len] = (unsigned char)(counter >> 24);
    block[seed_len + 1u] = (unsigned char)(counter >> 16);
    block[seed_len + 2u] = (unsigned char)(counter >> 8);
    block[seed_len + 3u] = (unsigned char)counter;
    result = rsa_hash_one(hash, block, seed_len + 4u, dig, &hlen, &prefix,
        &prefix_len);
    if (result != GSEC_OK) {
      gsec_wipe(block, sizeof block);
      gsec_wipe(dig, sizeof dig);
      return result;
    }
    take = hlen;
    if (take > mask_len - off) {
      take = mask_len - off;
    }
    for (i = 0; i < take; i++) {
      mask[off + i] = dig[i];
    }
    off += take;
    counter++;
    if (counter == 0) {
      gsec_wipe(block, sizeof block);
      gsec_wipe(dig, sizeof dig);
      return GSEC_ERR_LIMIT;
    }
  }
  gsec_wipe(block, sizeof block);
  gsec_wipe(dig, sizeof dig);
  (void)prefix;
  (void)prefix_len;
  return GSEC_OK;
}

void rsa_em_shape(const unsigned char * np, size_t k, size_t * em_len,
    unsigned * unused) {
  unsigned char top = np[0];
  unsigned count = 0;

  while ((top & 0x80u) == 0) {
    count++;
    top = (unsigned char)(top << 1);
  }
  if (count == 7u) {
    *em_len = k - 1u;
    *unused = 0;
  } else {
    *em_len = k;
    *unused = count + 1u;
  }
}
