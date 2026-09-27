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
 * RSA verification. The exponent is public, so the modular exponentiation
 * branches on its bits. PKCS#1 v1.5 is compared against one encoding.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/rsa.h>
#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/sha512.h>

#include "bn.h"
#include "rsa_pad.h"

#include <string.h>

static GSEC_Result recover(unsigned char * em, size_t k, const bn * mod,
    const unsigned char * exp, size_t exp_len, const void * sig, size_t sig_len) {
  bn s;
  bn m;

  if (sig == NULL) {
    return GSEC_ERR_INVALID;
  }
  if (sig_len != k) {
    return GSEC_ERR_MISMATCH;
  }
  if (!bn_from_be(&s, sig, sig_len)) {
    return GSEC_ERR_LIMIT;
  }
  if (bn_cmp(&s, mod) >= 0) {
    gsec_wipe(&s, sizeof s);
    return GSEC_ERR_MISMATCH;
  }
  if (!bn_modexp(&m, &s, exp, exp_len, mod)) {
    gsec_wipe(&s, sizeof s);
    gsec_wipe(&m, sizeof m);
    return GSEC_ERR_INVALID;
  }
  bn_to_be(em, k, &m);
  gsec_wipe(&s, sizeof s);
  gsec_wipe(&m, sizeof m);
  return GSEC_OK;
}

GSEC_Result gsec_rsa_pkcs1_v15_verify(uint32_t hash, const void * n,
    size_t n_len, const void * e, size_t e_len, const void * msg,
    size_t msg_len, const void * sig, size_t sig_len) {
  bn mod;
  const unsigned char * exp;
  const unsigned char * prefix;
  unsigned char em[GSEC_RSA_MODULUS_MAX];
  unsigned char expect[GSEC_RSA_MODULUS_MAX];
  unsigned char dig[GSEC_SHA512_DIGEST_LEN];
  size_t exp_len;
  size_t k;
  size_t hlen;
  size_t prefix_len;
  size_t tlen;
  GSEC_Result result;

  if (msg == NULL && msg_len != 0) {
    return GSEC_ERR_INVALID;
  }
  result = rsa_load_public(&mod, &exp, &exp_len, n, n_len, e, e_len, &k);
  if (result != GSEC_OK) {
    return result;
  }
  result = rsa_hash_one(hash, msg, msg_len, dig, &hlen, &prefix, &prefix_len);
  if (result != GSEC_OK) {
    gsec_wipe(&mod, sizeof mod);
    gsec_wipe(dig, sizeof dig);
    return result;
  }
  result = recover(em, k, &mod, exp, exp_len, sig, sig_len);
  if (result != GSEC_OK) {
    gsec_wipe(&mod, sizeof mod);
    gsec_wipe(dig, sizeof dig);
    gsec_wipe(em, sizeof em);
    return result;
  }
  tlen = prefix_len + hlen;
  if (k < tlen + 11u) {
    gsec_wipe(&mod, sizeof mod);
    gsec_wipe(dig, sizeof dig);
    gsec_wipe(em, sizeof em);
    return GSEC_ERR_MISMATCH;
  }
  memset(expect, 0xff, k);
  expect[0] = 0x00;
  expect[1] = 0x01;
  expect[k - tlen - 1u] = 0x00;
  memcpy(expect + (k - tlen), prefix, prefix_len);
  memcpy(expect + (k - hlen), dig, hlen);
  result = gsec_equal(em, expect, k);
  gsec_wipe(&mod, sizeof mod);
  gsec_wipe(dig, sizeof dig);
  gsec_wipe(em, sizeof em);
  gsec_wipe(expect, sizeof expect);
  if (result == GSEC_OK) {
    return GSEC_OK;
  }
  return GSEC_ERR_MISMATCH;
}

GSEC_Result gsec_rsa_pss_verify(uint32_t hash, uint32_t mgf_hash,
    const void * n, size_t n_len, const void * e, size_t e_len,
    const void * msg, size_t msg_len, const void * sig, size_t sig_len,
    size_t salt_len) {
  bn mod;
  const unsigned char * exp;
  const unsigned char * prefix;
  unsigned char em[GSEC_RSA_MODULUS_MAX];
  unsigned char db[GSEC_RSA_MODULUS_MAX];
  unsigned char mask[GSEC_RSA_MODULUS_MAX];
  unsigned char dig[GSEC_SHA512_DIGEST_LEN];
  unsigned char prime[8u + GSEC_SHA512_DIGEST_LEN + GSEC_RSA_MODULUS_MAX];
  unsigned char h2[GSEC_SHA512_DIGEST_LEN];
  size_t exp_len;
  const unsigned char * body;
  size_t k;
  size_t em_len;
  size_t hlen;
  size_t prefix_len;
  size_t db_len;
  size_t i;
  unsigned unused;
  GSEC_Result result;

  if (msg == NULL && msg_len != 0) {
    return GSEC_ERR_INVALID;
  }
  result = rsa_load_public(&mod, &exp, &exp_len, n, n_len, e, e_len, &k);
  if (result != GSEC_OK) {
    return result;
  }
  result = rsa_hash_one(hash, msg, msg_len, dig, &hlen, &prefix, &prefix_len);
  if (result != GSEC_OK) {
    gsec_wipe(&mod, sizeof mod);
    return result;
  }
  result = recover(em, k, &mod, exp, exp_len, sig, sig_len);
  if (result != GSEC_OK) {
    gsec_wipe(&mod, sizeof mod);
    gsec_wipe(dig, sizeof dig);
    return result;
  }
  /* RFC 8017 section 8.1.2: emBits is the modulus bit length minus one. */
  rsa_em_shape(((const unsigned char *)n) + (n_len - k), k, &em_len, &unused);
  if (em_len < hlen + salt_len + 2u || em[k - 1u] != 0xbc ||
      (em_len < k && em[0] != 0)) {
    gsec_wipe(&mod, sizeof mod);
    gsec_wipe(dig, sizeof dig);
    gsec_wipe(em, sizeof em);
    return GSEC_ERR_MISMATCH;
  }
  body = em + (k - em_len);
  if (unused > 0 && (body[0] >> (8u - unused)) != 0) {
    gsec_wipe(&mod, sizeof mod);
    gsec_wipe(dig, sizeof dig);
    gsec_wipe(em, sizeof em);
    return GSEC_ERR_MISMATCH;
  }
  db_len = em_len - hlen - 1u;
  result = rsa_mgf1(mgf_hash, body + db_len, hlen, mask, db_len);
  if (result != GSEC_OK) {
    gsec_wipe(&mod, sizeof mod);
    gsec_wipe(dig, sizeof dig);
    gsec_wipe(em, sizeof em);
    gsec_wipe(mask, sizeof mask);
    return result;
  }
  for (i = 0; i < db_len; i++) {
    db[i] = (unsigned char)(body[i] ^ mask[i]);
  }
  if (unused > 0) {
    db[0] = (unsigned char)(db[0] & (unsigned char)(0xffu >> unused));
  }
  if (db_len < salt_len + 1u) {
    result = GSEC_ERR_MISMATCH;
  } else {
    size_t ps = db_len - salt_len - 1u;

    result = GSEC_OK;
    for (i = 0; i < ps; i++) {
      if (db[i] != 0) {
        result = GSEC_ERR_MISMATCH;
      }
    }
    if (db[ps] != 0x01) {
      result = GSEC_ERR_MISMATCH;
    }
    if (result == GSEC_OK) {
      memset(prime, 0, 8);
      memcpy(prime + 8, dig, hlen);
      memcpy(prime + 8u + hlen, db + ps + 1u, salt_len);
      result = rsa_hash_one(hash, prime, 8u + hlen + salt_len, h2, &hlen, &prefix,
          &prefix_len);
      if (result == GSEC_OK &&
          gsec_equal(h2, body + db_len, hlen) != GSEC_OK) {
        result = GSEC_ERR_MISMATCH;
      }
    }
  }
  gsec_wipe(&mod, sizeof mod);
  gsec_wipe(dig, sizeof dig);
  gsec_wipe(em, sizeof em);
  gsec_wipe(db, sizeof db);
  gsec_wipe(mask, sizeof mask);
  gsec_wipe(prime, sizeof prime);
  gsec_wipe(h2, sizeof h2);
  return result == GSEC_OK ? GSEC_OK : (result == GSEC_ERR_MISMATCH ?
      GSEC_ERR_MISMATCH : result);
}
