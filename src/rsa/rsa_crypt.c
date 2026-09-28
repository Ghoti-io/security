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
 * RSA encryption. The private exponent goes through rsa_blinded, the same
 * exponentiation signing uses. PKCS#1 v1.5 and OAEP both scan the encoded
 * message with arithmetic and branch only on the answer the caller sees.
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

static uint32_t bit_of(uint32_t x) {
  x |= x >> 16;
  x |= x >> 8;
  x |= x >> 4;
  x |= x >> 2;
  x |= x >> 1;
  return x & 1u;
}

static uint32_t eq_u32(uint32_t a, uint32_t b) {
  return bit_of(a ^ b) ^ 1u;
}

static uint32_t below_u32(uint32_t a, uint32_t b) {
  return (a - b) >> 31;
}

static void mark_public(void * p, size_t n) {
#if defined(GSEC_CT_TEST)
  VALGRIND_MAKE_MEM_DEFINED(p, n);
#else
  (void)p;
  (void)n;
#endif
}

static GSEC_Result hash_len(uint32_t hash, size_t * hlen) {
  if (hash == GSEC_RSA_MD5) {
    *hlen = 16u;
  } else if (hash == GSEC_RSA_SHA1) {
    *hlen = 20u;
  } else if (hash == GSEC_RSA_SHA256) {
    *hlen = 32u;
  } else if (hash == GSEC_RSA_SHA384) {
    *hlen = 48u;
  } else if (hash == GSEC_RSA_SHA512) {
    *hlen = 64u;
  } else {
    return GSEC_ERR_INVALID;
  }
  return GSEC_OK;
}

static GSEC_Result apply_public(unsigned char * out, size_t k, const bn * mod,
    const unsigned char * e, size_t e_len, const unsigned char * em) {
  bn m;
  bn c;

  if (!bn_from_be(&m, em, k)) {
    return GSEC_ERR_LIMIT;
  }
  if (bn_cmp(&m, mod) >= 0) {
    gsec_wipe(&m, sizeof m);
    return GSEC_ERR_INVALID;
  }
  if (!bn_modexp(&c, &m, e, e_len, mod)) {
    gsec_wipe(&m, sizeof m);
    gsec_wipe(&c, sizeof c);
    return GSEC_ERR_INVALID;
  }
  bn_to_be(out, k, &c);
  gsec_wipe(&m, sizeof m);
  gsec_wipe(&c, sizeof c);
  return GSEC_OK;
}

static GSEC_Result nonzero_pad(unsigned char * ps, size_t n) {
  size_t filled = 0;

  while (filled < n) {
    unsigned char draw[GSEC_RSA_MODULUS_MAX];
    size_t want = n - filled;
    size_t i;
    GSEC_Result result;

    if (want > sizeof draw) {
      want = sizeof draw;
    }
    result = gsec_random_bytes(draw, want, NULL);
    if (result != GSEC_OK) {
      gsec_wipe(draw, sizeof draw);
      return result;
    }
    for (i = 0; i < want; i++) {
      if (draw[i] != 0) {
        ps[filled] = draw[i];
        filled++;
      }
    }
    gsec_wipe(draw, sizeof draw);
  }
  return GSEC_OK;
}

static void take_msg(unsigned char * plain, size_t k, const unsigned char * em,
    uint32_t start, uint32_t mlen) {
  const volatile unsigned char * secret = em;
  size_t i;

  memset(plain, 0, k);
  for (i = 0; i < k; i++) {
    uint32_t src = start + (uint32_t)i;
    uint32_t use = below_u32((uint32_t)i, mlen);
    volatile unsigned char acc = 0;
    size_t j;

    for (j = 0; j < k; j++) {
      uint32_t match = eq_u32((uint32_t)j, src);
      acc = (unsigned char)(acc | (unsigned char)(secret[j] & (0u - match)));
    }
    plain[i] = (unsigned char)(acc & (unsigned char)(0u - use));
  }
}

static GSEC_Result finish_msg(unsigned char * msg, size_t msg_cap,
    size_t * msg_len, unsigned char * plain, size_t k, uint32_t ok,
    uint32_t mlen) {
  mark_public(&ok, sizeof ok);
  mark_public(&mlen, sizeof mlen);
  mark_public(plain, k);
  if (ok == 0) {
    gsec_wipe(plain, k);
    gsec_wipe(msg, msg_cap < k ? msg_cap : k);
    return GSEC_ERR_MISMATCH;
  }
  if ((size_t)mlen > msg_cap) {
    gsec_wipe(plain, k);
    gsec_wipe(msg, msg_cap < k ? msg_cap : k);
    return GSEC_ERR_LIMIT;
  }
  if (mlen > 0) {
    memcpy(msg, plain, mlen);
  }
  *msg_len = mlen;
  gsec_wipe(plain, k);
  return GSEC_OK;
}

static GSEC_Result open_private(bn * mod, bn * priv, const unsigned char ** exp,
    size_t * exp_len, size_t * k, const void * n, size_t n_len, const void * e,
    size_t e_len, const void * d, size_t d_len, const void * cipher,
    size_t cipher_len, void * msg, size_t * msg_len) {
  GSEC_Result result;

  if (msg == NULL || msg_len == NULL) {
    return GSEC_ERR_INVALID;
  }
  result = rsa_load_public(mod, exp, exp_len, n, n_len, e, e_len, k);
  if (result != GSEC_OK) {
    return result;
  }
  if (cipher == NULL || cipher_len != *k) {
    gsec_wipe(mod, sizeof *mod);
    return GSEC_ERR_MISMATCH;
  }
  result = rsa_load_private(priv, mod, d, d_len);
  if (result != GSEC_OK) {
    gsec_wipe(mod, sizeof *mod);
    return result;
  }
  return GSEC_OK;
}

GSEC_Result gsec_rsa_pkcs1_v15_encrypt(const void * n, size_t n_len,
    const void * e, size_t e_len, const void * msg, size_t msg_len, void * out,
    size_t out_len) {
  bn mod;
  const unsigned char * exp = NULL;
  unsigned char em[GSEC_RSA_MODULUS_MAX];
  size_t exp_len = 0;
  size_t k = 0;
  size_t ps_len;
  GSEC_Result result;

  if (msg == NULL && msg_len != 0) {
    return GSEC_ERR_INVALID;
  }
  result = rsa_load_public(&mod, &exp, &exp_len, n, n_len, e, e_len, &k);
  if (result != GSEC_OK) {
    return result;
  }
  if (out == NULL || out_len != k || msg_len > k || k < msg_len + 11u) {
    gsec_wipe(&mod, sizeof mod);
    if (out != NULL && out_len == k) {
      gsec_wipe(out, out_len);
    }
    return GSEC_ERR_INVALID;
  }
  em[0] = 0x00;
  em[1] = 0x02;
  ps_len = k - msg_len - 3u;
  result = nonzero_pad(em + 2, ps_len);
  if (result != GSEC_OK) {
    gsec_wipe(&mod, sizeof mod);
    gsec_wipe(em, sizeof em);
    gsec_wipe(out, out_len);
    return result;
  }
  em[2u + ps_len] = 0x00;
  if (msg_len > 0) {
    memcpy(em + 3u + ps_len, msg, msg_len);
  }
  result = apply_public(out, k, &mod, exp, exp_len, em);
  gsec_wipe(&mod, sizeof mod);
  gsec_wipe(em, sizeof em);
  if (result != GSEC_OK) {
    gsec_wipe(out, out_len);
  }
  return result;
}

GSEC_Result gsec_rsa_pkcs1_v15_decrypt(const void * n, size_t n_len,
    const void * e, size_t e_len, const void * d, size_t d_len,
    const void * cipher, size_t cipher_len, void * msg, size_t msg_cap,
    size_t * msg_len) {
  bn mod;
  bn priv;
  const unsigned char * exp = NULL;
  unsigned char em[GSEC_RSA_MODULUS_MAX];
  unsigned char plain[GSEC_RSA_MODULUS_MAX];
  const volatile unsigned char * secret;
  size_t exp_len = 0;
  size_t k = 0;
  size_t i;
  uint32_t found = 0;
  uint32_t sep = 0;
  uint32_t ok;
  uint32_t mlen;
  GSEC_Result result;

  result = open_private(&mod, &priv, &exp, &exp_len, &k, n, n_len, e, e_len, d,
      d_len, cipher, cipher_len, msg, msg_len);
  if (result != GSEC_OK) {
    return result;
  }
  result = rsa_blinded(em, k, &mod, exp, exp_len, &priv, cipher);
  gsec_wipe(&mod, sizeof mod);
  gsec_wipe(&priv, sizeof priv);
  if (result != GSEC_OK) {
    gsec_wipe(em, sizeof em);
    gsec_wipe(msg, msg_cap < k ? msg_cap : k);
    return result;
  }
  secret = em;
  ok = eq_u32(secret[0], 0x00) & eq_u32(secret[1], 0x02);
  for (i = 2; i < k; i++) {
    uint32_t is_zero = eq_u32(secret[i], 0x00);
    uint32_t take = (found ^ 1u) & is_zero;

    sep |= (uint32_t)i & (0u - take);
    found |= is_zero;
  }
  ok &= found;
  ok &= (9u - sep) >> 31;
  mlen = (uint32_t)k - sep - 1u;
  take_msg(plain, k, em, sep + 1u, mlen);
  gsec_wipe(em, sizeof em);
  return finish_msg(msg, msg_cap, msg_len, plain, k, ok, mlen);
}

static GSEC_Result mgf(uint32_t hash, const unsigned char * seed,
    size_t seed_len, unsigned char * mask, size_t mask_len) {
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
  return GSEC_OK;
}

static GSEC_Result label_hash(uint32_t hash, const void * label,
    size_t label_len, unsigned char * out, size_t * hlen) {
  unsigned char dig[GSEC_SHA512_DIGEST_LEN];
  const unsigned char * prefix;
  size_t prefix_len;
  static const unsigned char empty = 0;
  const void * data = label_len == 0 ? (const void *)&empty : label;
  GSEC_Result result;

  result = rsa_hash_one(hash, data, label_len, dig, hlen, &prefix,
      &prefix_len);
  if (result != GSEC_OK) {
    gsec_wipe(dig, sizeof dig);
    return result;
  }
  memcpy(out, dig, *hlen);
  gsec_wipe(dig, sizeof dig);
  (void)prefix;
  return GSEC_OK;
}

GSEC_Result gsec_rsa_oaep_mgf_encrypt(uint32_t hash, uint32_t mgf_hash,
    const void * n, size_t n_len, const void * e, size_t e_len,
    const void * label, size_t label_len, const void * msg, size_t msg_len,
    void * out, size_t out_len) {
  bn mod;
  const unsigned char * exp = NULL;
  unsigned char em[GSEC_RSA_MODULUS_MAX];
  unsigned char db[GSEC_RSA_MODULUS_MAX];
  unsigned char seed[GSEC_SHA512_DIGEST_LEN];
  unsigned char mask[GSEC_RSA_MODULUS_MAX];
  unsigned char lhash[GSEC_SHA512_DIGEST_LEN];
  size_t exp_len = 0;
  size_t k = 0;
  size_t hlen = 0;
  size_t db_len;
  size_t i;
  GSEC_Result result;

  if ((label == NULL && label_len != 0) || (msg == NULL && msg_len != 0)) {
    return GSEC_ERR_INVALID;
  }
  {
    size_t mgf_len = 0;

    result = hash_len(mgf_hash, &mgf_len);
    if (result != GSEC_OK) {
      return result;
    }
  }
  result = hash_len(hash, &hlen);
  if (result != GSEC_OK) {
    return result;
  }
  result = rsa_load_public(&mod, &exp, &exp_len, n, n_len, e, e_len, &k);
  if (result != GSEC_OK) {
    return result;
  }
  if (out == NULL || out_len != k || k < 2u * hlen + 2u ||
      msg_len > k - 2u * hlen - 2u) {
    gsec_wipe(&mod, sizeof mod);
    if (out != NULL && out_len == k) {
      gsec_wipe(out, out_len);
    }
    return GSEC_ERR_INVALID;
  }
  result = label_hash(hash, label, label_len, lhash, &hlen);
  if (result != GSEC_OK) {
    gsec_wipe(&mod, sizeof mod);
    gsec_wipe(out, out_len);
    return result;
  }
  db_len = k - hlen - 1u;
  memset(db, 0, db_len);
  memcpy(db, lhash, hlen);
  db[db_len - msg_len - 1u] = 0x01;
  if (msg_len > 0) {
    memcpy(db + (db_len - msg_len), msg, msg_len);
  }
  result = gsec_random_bytes(seed, hlen, NULL);
  if (result != GSEC_OK) {
    goto fail;
  }
  result = mgf(mgf_hash, seed, hlen, mask, db_len);
  if (result != GSEC_OK) {
    goto fail;
  }
  for (i = 0; i < db_len; i++) {
    db[i] = (unsigned char)(db[i] ^ mask[i]);
  }
  result = mgf(mgf_hash, db, db_len, mask, hlen);
  if (result != GSEC_OK) {
    goto fail;
  }
  em[0] = 0x00;
  for (i = 0; i < hlen; i++) {
    em[1u + i] = (unsigned char)(seed[i] ^ mask[i]);
  }
  memcpy(em + 1u + hlen, db, db_len);
  result = apply_public(out, k, &mod, exp, exp_len, em);
  gsec_wipe(&mod, sizeof mod);
  gsec_wipe(em, sizeof em);
  gsec_wipe(db, sizeof db);
  gsec_wipe(seed, sizeof seed);
  gsec_wipe(mask, sizeof mask);
  gsec_wipe(lhash, sizeof lhash);
  if (result != GSEC_OK) {
    gsec_wipe(out, out_len);
  }
  return result;
fail:
  gsec_wipe(&mod, sizeof mod);
  gsec_wipe(em, sizeof em);
  gsec_wipe(db, sizeof db);
  gsec_wipe(seed, sizeof seed);
  gsec_wipe(mask, sizeof mask);
  gsec_wipe(lhash, sizeof lhash);
  gsec_wipe(out, out_len);
  return result;
}

GSEC_Result gsec_rsa_oaep_mgf_decrypt(uint32_t hash, uint32_t mgf_hash,
    const void * n, size_t n_len, const void * e, size_t e_len,
    const void * d, size_t d_len, const void * label, size_t label_len,
    const void * cipher, size_t cipher_len, void * msg, size_t msg_cap,
    size_t * msg_len) {
  bn mod;
  bn priv;
  const unsigned char * exp = NULL;
  unsigned char em[GSEC_RSA_MODULUS_MAX];
  unsigned char db[GSEC_RSA_MODULUS_MAX];
  unsigned char seed[GSEC_SHA512_DIGEST_LEN];
  unsigned char mask[GSEC_RSA_MODULUS_MAX];
  unsigned char lhash[GSEC_SHA512_DIGEST_LEN];
  unsigned char plain[GSEC_RSA_MODULUS_MAX];
  const volatile unsigned char * secret;
  const volatile unsigned char * dbv;
  size_t exp_len = 0;
  size_t k = 0;
  size_t hlen = 0;
  size_t db_len;
  size_t i;
  uint32_t found = 0;
  uint32_t bad = 0;
  uint32_t sep = 0;
  uint32_t ok;
  uint32_t mlen;
  uint32_t ldiff = 0;
  GSEC_Result result;

  if (label == NULL && label_len != 0) {
    return GSEC_ERR_INVALID;
  }
  {
    size_t mgf_len = 0;

    result = hash_len(mgf_hash, &mgf_len);
    if (result != GSEC_OK) {
      return result;
    }
  }
  result = hash_len(hash, &hlen);
  if (result != GSEC_OK) {
    return result;
  }
  result = open_private(&mod, &priv, &exp, &exp_len, &k, n, n_len, e, e_len, d,
      d_len, cipher, cipher_len, msg, msg_len);
  if (result != GSEC_OK) {
    return result;
  }
  if (k < 2u * hlen + 2u) {
    gsec_wipe(&mod, sizeof mod);
    gsec_wipe(&priv, sizeof priv);
    return GSEC_ERR_INVALID;
  }
  result = label_hash(hash, label, label_len, lhash, &hlen);
  if (result != GSEC_OK) {
    gsec_wipe(&mod, sizeof mod);
    gsec_wipe(&priv, sizeof priv);
    return result;
  }
  result = rsa_blinded(em, k, &mod, exp, exp_len, &priv, cipher);
  gsec_wipe(&mod, sizeof mod);
  gsec_wipe(&priv, sizeof priv);
  if (result != GSEC_OK) {
    gsec_wipe(em, sizeof em);
    gsec_wipe(lhash, sizeof lhash);
    gsec_wipe(msg, msg_cap < k ? msg_cap : k);
    return result;
  }
  secret = em;
  db_len = k - hlen - 1u;
  result = mgf(mgf_hash, em + 1u + hlen, db_len, mask, hlen);
  if (result != GSEC_OK) {
    goto fail_em;
  }
  for (i = 0; i < hlen; i++) {
    seed[i] = (unsigned char)(secret[1u + i] ^ mask[i]);
  }
  result = mgf(mgf_hash, seed, hlen, db, db_len);
  if (result != GSEC_OK) {
    goto fail_em;
  }
  for (i = 0; i < db_len; i++) {
    db[i] = (unsigned char)(db[i] ^ secret[1u + hlen + i]);
  }
  dbv = db;
  for (i = 0; i < hlen; i++) {
    ldiff |= (uint32_t)(dbv[i] ^ lhash[i]);
  }
  ok = eq_u32(secret[0], 0x00) & (bit_of(ldiff) ^ 1u);
  for (i = hlen; i < db_len; i++) {
    uint32_t is_one = eq_u32(dbv[i], 0x01);
    uint32_t is_zero = eq_u32(dbv[i], 0x00);
    uint32_t looking = found ^ 1u;
    uint32_t take = looking & is_one;

    sep |= (uint32_t)i & (0u - take);
    found |= take;
    bad |= looking & (is_zero ^ 1u) & (is_one ^ 1u);
  }
  ok &= found & (bad ^ 1u);
  mlen = (uint32_t)db_len - sep - 1u;
  take_msg(plain, k, db, sep + 1u, mlen);
  gsec_wipe(em, sizeof em);
  gsec_wipe(db, sizeof db);
  gsec_wipe(seed, sizeof seed);
  gsec_wipe(mask, sizeof mask);
  gsec_wipe(lhash, sizeof lhash);
  return finish_msg(msg, msg_cap, msg_len, plain, k, ok, mlen);
fail_em:
  gsec_wipe(em, sizeof em);
  gsec_wipe(db, sizeof db);
  gsec_wipe(seed, sizeof seed);
  gsec_wipe(mask, sizeof mask);
  gsec_wipe(lhash, sizeof lhash);
  gsec_wipe(msg, msg_cap < k ? msg_cap : k);
  return result;
}

GSEC_Result gsec_rsa_oaep_encrypt(uint32_t hash, const void * n, size_t n_len,
    const void * e, size_t e_len, const void * label, size_t label_len,
    const void * msg, size_t msg_len, void * out, size_t out_len) {
  return gsec_rsa_oaep_mgf_encrypt(hash, hash, n, n_len, e, e_len, label,
      label_len, msg, msg_len, out, out_len);
}

GSEC_Result gsec_rsa_oaep_decrypt(uint32_t hash, const void * n, size_t n_len,
    const void * e, size_t e_len, const void * d, size_t d_len,
    const void * label, size_t label_len, const void * cipher,
    size_t cipher_len, void * msg, size_t msg_cap, size_t * msg_len) {
  return gsec_rsa_oaep_mgf_decrypt(hash, hash, n, n_len, e, e_len, d, d_len,
      label, label_len, cipher, cipher_len, msg, msg_cap, msg_len);
}
