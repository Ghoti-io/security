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
 * RSA signing. The private exponent is raised with bn_modexp_ct. The base
 * is m * r^e, and the result is multiplied by the inverse of r, so the
 * signature bytes are still m^d mod n. r comes from the kernel generator.
 * A factor shared with the modulus would not invert; the public exponent
 * checks the signature, and eight failures return an internal error
 * rather than a value that does not verify.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/random.h>
#include <ghoti.io/security/rsa.h>
#include <ghoti.io/security/secret.h>

#include "bn.h"
#include "rsa_pad.h"

#include <string.h>

#if defined(GSEC_CT_TEST)
#include <valgrind/memcheck.h>
#endif

static uint32_t fold32(uint32_t acc) {
  acc |= acc >> 16;
  acc |= acc >> 8;
  acc |= acc >> 4;
  acc |= acc >> 2;
  acc |= acc >> 1;
  return acc & 1u;
}

static int publish(uint32_t bit) {
#if defined(GSEC_CT_TEST)
  VALGRIND_MAKE_MEM_DEFINED(&bit, sizeof bit);
#endif
  return bit != 0;
}

static uint32_t bn_same(const bn * a, const bn * b) {
  uint32_t diff = 0;
  int i;
  int n = a->n > b->n ? a->n : b->n;

  for (i = 0; i < n; i++) {
    uint32_t av = i < a->n ? a->v[i] : 0;
    uint32_t bv = i < b->n ? b->v[i] : 0;

    diff |= av ^ bv;
  }
  return fold32(diff) ^ 1u;
}

GSEC_Result rsa_load_private(bn * d, const bn * mod, const void * raw,
    size_t raw_len) {
  const unsigned char * p = raw;
  size_t n = raw_len;
  uint32_t hi = 0;
  size_t i;

  if (raw == NULL || raw_len == 0) {
    return GSEC_ERR_INVALID;
  }
  if (raw_len > GSEC_RSA_MODULUS_MAX + 8u) {
    return GSEC_ERR_LIMIT;
  }
  if (n > GSEC_RSA_MODULUS_MAX) {
    for (i = 0; i < n - GSEC_RSA_MODULUS_MAX; i++) {
      hi |= p[i];
    }
    p += n - GSEC_RSA_MODULUS_MAX;
    n = GSEC_RSA_MODULUS_MAX;
  }
  if (!publish(fold32(hi) ^ 1u)) {
    return GSEC_ERR_INVALID;
  }
  if (!bn_from_be(d, p, n)) {
    return GSEC_ERR_LIMIT;
  }
  hi = 0;
  for (i = (size_t)mod->n; i < (size_t)d->n; i++) {
    hi |= d->v[i];
  }
  if (!publish(fold32(hi) ^ 1u)) {
    gsec_wipe(d, sizeof *d);
    return GSEC_ERR_INVALID;
  }
  d->n = mod->n;
  if (!publish(bn_below(d, mod) & bn_nonzero(d))) {
    gsec_wipe(d, sizeof *d);
    return GSEC_ERR_INVALID;
  }
  return GSEC_OK;
}

GSEC_Result rsa_blinded(unsigned char * sig, size_t k, const bn * mod,
    const unsigned char * e, size_t e_len, const bn * d,
    const unsigned char * em) {
  bn m;
  bn r;
  bn re;
  bn base;
  bn raised;
  bn inv;
  bn s;
  bn check;
  unsigned char rbytes[GSEC_RSA_MODULUS_MAX];
  GSEC_Result result = GSEC_ERR_INTERNAL;
  int attempt;
  int i;

  memset(&m, 0, sizeof m);
  memset(&r, 0, sizeof r);
  memset(&re, 0, sizeof re);
  memset(&base, 0, sizeof base);
  memset(&raised, 0, sizeof raised);
  memset(&inv, 0, sizeof inv);
  memset(&s, 0, sizeof s);
  memset(&check, 0, sizeof check);
  memset(rbytes, 0, sizeof rbytes);
  if (!bn_from_be(&m, em, k)) {
    result = GSEC_ERR_LIMIT;
    goto out;
  }
  for (i = m.n; i < BN_LIMBS; i++) {
    m.v[i] = 0;
  }
  m.n = mod->n;
  if (!publish(bn_below(&m, mod))) {
    result = GSEC_ERR_INVALID;
    goto out;
  }
  for (attempt = 0; attempt < 8; attempt++) {
    result = gsec_random_bytes(rbytes, k, NULL);
    if (result != GSEC_OK) {
      goto out;
    }
    if (!bn_from_be(&r, rbytes, k)) {
      result = GSEC_ERR_LIMIT;
      goto out;
    }
    bn_reduce_ct(&r, mod);
    if (!publish(bn_nonzero(&r))) {
      continue;
    }
    if (!bn_modexp(&re, &r, e, e_len, mod) ||
        !bn_modmul(&base, &m, &re, mod) ||
        !bn_modexp_ct(&raised, &base, d, mod) ||
        !bn_modinv_ct(&inv, &r, mod) ||
        !bn_modmul(&s, &raised, &inv, mod) ||
        !bn_modexp(&check, &s, e, e_len, mod)) {
      result = GSEC_ERR_INTERNAL;
      goto out;
    }
    bn_to_be(sig, k, &s);
    if (publish(bn_same(&check, &m))) {
      result = GSEC_OK;
      goto out;
    }
  }
  result = GSEC_ERR_INTERNAL;
out:
  if (result != GSEC_OK) {
    gsec_wipe(sig, k);
  }
  gsec_wipe(&m, sizeof m);
  gsec_wipe(&r, sizeof r);
  gsec_wipe(&re, sizeof re);
  gsec_wipe(&base, sizeof base);
  gsec_wipe(&raised, sizeof raised);
  gsec_wipe(&inv, sizeof inv);
  gsec_wipe(&s, sizeof s);
  gsec_wipe(&check, sizeof check);
  gsec_wipe(rbytes, sizeof rbytes);
  return result;
}

static GSEC_Result pkcs1_em(uint32_t hash, const void * msg, size_t msg_len,
    size_t k, unsigned char em[GSEC_RSA_MODULUS_MAX]) {
  unsigned char dig[GSEC_SHA512_DIGEST_LEN];
  const unsigned char * prefix = NULL;
  size_t hlen = 0;
  size_t prefix_len = 0;
  size_t tlen;
  GSEC_Result result;

  result = rsa_hash_one(hash, msg, msg_len, dig, &hlen, &prefix, &prefix_len);
  if (result != GSEC_OK) {
    gsec_wipe(dig, sizeof dig);
    return result;
  }
  tlen = prefix_len + hlen;
  if (k < tlen + 11u) {
    gsec_wipe(dig, sizeof dig);
    return GSEC_ERR_INVALID;
  }
  memset(em, 0xff, k);
  em[0] = 0x00;
  em[1] = 0x01;
  em[k - tlen - 1u] = 0x00;
  memcpy(em + (k - tlen), prefix, prefix_len);
  memcpy(em + (k - hlen), dig, hlen);
  gsec_wipe(dig, sizeof dig);
  return GSEC_OK;
}

static GSEC_Result pss_em(uint32_t hash, uint32_t mgf_hash, const void * msg,
    size_t msg_len, const unsigned char * np, size_t k, const void * salt,
    size_t salt_len, unsigned char em[GSEC_RSA_MODULUS_MAX]) {
  unsigned char dig[GSEC_SHA512_DIGEST_LEN];
  unsigned char hash2[GSEC_SHA512_DIGEST_LEN];
  unsigned char stored[GSEC_RSA_MODULUS_MAX];
  unsigned char db[GSEC_RSA_MODULUS_MAX];
  unsigned char mask[GSEC_RSA_MODULUS_MAX];
  unsigned char prime[8u + GSEC_SHA512_DIGEST_LEN + GSEC_RSA_MODULUS_MAX];
  const unsigned char * prefix = NULL;
  unsigned char * body;
  size_t hlen = 0;
  size_t prefix_len = 0;
  size_t hlen2 = 0;
  size_t em_len = 0;
  size_t db_len;
  size_t ps;
  size_t i;
  unsigned unused = 0;
  GSEC_Result result;

  if (salt == NULL && salt_len != 0) {
    return GSEC_ERR_INVALID;
  }
  if (salt_len > GSEC_RSA_MODULUS_MAX) {
    return GSEC_ERR_INVALID;
  }
  result = rsa_hash_one(hash, msg, msg_len, dig, &hlen, &prefix, &prefix_len);
  if (result != GSEC_OK) {
    gsec_wipe(dig, sizeof dig);
    return result;
  }
  rsa_em_shape(np, k, &em_len, &unused);
  if (em_len < hlen + salt_len + 2u) {
    gsec_wipe(dig, sizeof dig);
    return GSEC_ERR_INVALID;
  }
  if (salt_len > 0) {
    memcpy(stored, salt, salt_len);
  }
  memset(prime, 0, 8);
  memcpy(prime + 8, dig, hlen);
  if (salt_len > 0) {
    memcpy(prime + 8u + hlen, stored, salt_len);
  }
  result = rsa_hash_one(hash, prime, 8u + hlen + salt_len, hash2, &hlen2,
      &prefix, &prefix_len);
  if (result != GSEC_OK) {
    gsec_wipe(dig, sizeof dig);
    gsec_wipe(stored, sizeof stored);
    gsec_wipe(prime, sizeof prime);
    gsec_wipe(hash2, sizeof hash2);
    return result;
  }
  db_len = em_len - hlen - 1u;
  ps = db_len - salt_len - 1u;
  memset(db, 0, db_len);
  db[ps] = 0x01;
  if (salt_len > 0) {
    memcpy(db + ps + 1u, stored, salt_len);
  }
  result = rsa_mgf1(mgf_hash, hash2, hlen, mask, db_len);
  if (result != GSEC_OK) {
    gsec_wipe(dig, sizeof dig);
    gsec_wipe(stored, sizeof stored);
    gsec_wipe(prime, sizeof prime);
    gsec_wipe(hash2, sizeof hash2);
    gsec_wipe(db, sizeof db);
    gsec_wipe(mask, sizeof mask);
    return result;
  }
  memset(em, 0, k);
  body = em + (k - em_len);
  for (i = 0; i < db_len; i++) {
    body[i] = (unsigned char)(db[i] ^ mask[i]);
  }
  if (unused > 0) {
    body[0] = (unsigned char)(body[0] & (unsigned char)(0xffu >> unused));
  }
  memcpy(body + db_len, hash2, hlen);
  body[em_len - 1u] = 0xbc;
  gsec_wipe(dig, sizeof dig);
  gsec_wipe(stored, sizeof stored);
  gsec_wipe(prime, sizeof prime);
  gsec_wipe(hash2, sizeof hash2);
  gsec_wipe(db, sizeof db);
  gsec_wipe(mask, sizeof mask);
  return GSEC_OK;
}

static const unsigned char * stripped(const void * n, size_t n_len, size_t k) {
  return (const unsigned char *)n + (n_len - k);
}

GSEC_Result gsec_rsa_private_pkcs1_v15_sign(uint32_t hash, const void * n,
    size_t n_len, const void * e, size_t e_len, const void * d, size_t d_len,
    const void * msg, size_t msg_len, void * sig, size_t sig_len) {
  bn mod;
  bn priv;
  const unsigned char * exp = NULL;
  unsigned char em[GSEC_RSA_MODULUS_MAX];
  size_t exp_len = 0;
  size_t k = 0;
  GSEC_Result result;

  if (msg == NULL && msg_len != 0) {
    return GSEC_ERR_INVALID;
  }
  result = rsa_load_public(&mod, &exp, &exp_len, n, n_len, e, e_len, &k);
  if (result != GSEC_OK) {
    return result;
  }
  if (sig == NULL || sig_len != k) {
    gsec_wipe(&mod, sizeof mod);
    return GSEC_ERR_INVALID;
  }
  result = rsa_load_private(&priv, &mod, d, d_len);
  if (result != GSEC_OK) {
    gsec_wipe(&mod, sizeof mod);
    gsec_wipe(sig, sig_len);
    return result;
  }
  result = pkcs1_em(hash, msg, msg_len, k, em);
  if (result != GSEC_OK) {
    gsec_wipe(&mod, sizeof mod);
    gsec_wipe(&priv, sizeof priv);
    gsec_wipe(em, sizeof em);
    gsec_wipe(sig, sig_len);
    return result;
  }
  result = rsa_blinded(sig, k, &mod, exp, exp_len, &priv, em);
  gsec_wipe(&mod, sizeof mod);
  gsec_wipe(&priv, sizeof priv);
  gsec_wipe(em, sizeof em);
  return result;
}

GSEC_Result gsec_rsa_private_pss_sign(uint32_t hash, uint32_t mgf_hash,
    const void * n, size_t n_len, const void * e, size_t e_len, const void * d,
    size_t d_len, const void * msg, size_t msg_len, void * sig, size_t sig_len,
    const void * salt, size_t salt_len) {
  bn mod;
  bn priv;
  const unsigned char * exp = NULL;
  unsigned char em[GSEC_RSA_MODULUS_MAX];
  size_t exp_len = 0;
  size_t k = 0;
  GSEC_Result result;

  if (msg == NULL && msg_len != 0) {
    return GSEC_ERR_INVALID;
  }
  result = rsa_load_public(&mod, &exp, &exp_len, n, n_len, e, e_len, &k);
  if (result != GSEC_OK) {
    return result;
  }
  if (sig == NULL || sig_len != k) {
    gsec_wipe(&mod, sizeof mod);
    return GSEC_ERR_INVALID;
  }
  result = rsa_load_private(&priv, &mod, d, d_len);
  if (result != GSEC_OK) {
    gsec_wipe(&mod, sizeof mod);
    gsec_wipe(sig, sig_len);
    return result;
  }
  result = pss_em(hash, mgf_hash, msg, msg_len, stripped(n, n_len, k), k, salt,
      salt_len, em);
  if (result != GSEC_OK) {
    gsec_wipe(&mod, sizeof mod);
    gsec_wipe(&priv, sizeof priv);
    gsec_wipe(em, sizeof em);
    gsec_wipe(sig, sig_len);
    return result;
  }
  result = rsa_blinded(sig, k, &mod, exp, exp_len, &priv, em);
  gsec_wipe(&mod, sizeof mod);
  gsec_wipe(&priv, sizeof priv);
  gsec_wipe(em, sizeof em);
  return result;
}
