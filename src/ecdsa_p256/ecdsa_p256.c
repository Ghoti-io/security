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
 * ECDSA P-256. The nonce is RFC 6979, so signing does not read the
 * entropy source. The scalar arithmetic is src/p256/sc_p256.c.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/ecdsa_p256.h>
#include <ghoti.io/security/hmac.h>
#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/sha256.h>

#include "../p256/p256_point.h"
#include "../p256/sc_p256.h"

#include <string.h>

#if defined(GSEC_CT_TEST)
#include <valgrind/memcheck.h>
#endif

static int publish(uint32_t bit) {
#if defined(GSEC_CT_TEST)
  VALGRIND_MAKE_MEM_DEFINED(&bit, sizeof bit);
#endif
  return bit != 0;
}

static int scalar_ok(const unsigned char in[GSEC_ECDSA_P256_LEN], sc_p256 * d) {
  unsigned char bytes[GSEC_ECDSA_P256_LEN];
  unsigned char zero[GSEC_ECDSA_P256_LEN];
  int i;
  int ok;

  sc_p256_set_bytes(d, in);
  sc_p256_to_bytes(bytes, d);
  for (i = 0; i < (int)sizeof zero; i++) {
    zero[i] = 0;
  }
  ok = publish(sc_p256_lt_n(d)) &&
      gsec_equal(bytes, zero, sizeof zero) != GSEC_OK;
  gsec_wipe(bytes, sizeof bytes);
  gsec_wipe(zero, sizeof zero);
  return ok;
}

static GSEC_Result hmac_sha256(const unsigned char key[GSEC_SHA256_DIGEST_LEN],
    const void * data, size_t n, unsigned char out[GSEC_SHA256_DIGEST_LEN]) {
  return gsec_hmac(GSEC_HMAC_SHA256, key, GSEC_SHA256_DIGEST_LEN, data, n, out);
}

GSEC_Result gsec_ecdsa_p256_public(const void * scalar, void * out) {
  unsigned char scalar_copy[GSEC_ECDSA_P256_LEN];
  unsigned char raw[GSEC_ECDSA_P256_PUBLIC_LEN];
  sc_p256 d;
  fe_p256 x;
  fe_p256 y;

  if (scalar == NULL || out == NULL) {
    return GSEC_ERR_INVALID;
  }
  memcpy(scalar_copy, scalar, sizeof scalar_copy);
  if (!scalar_ok(scalar_copy, &d)) {
    gsec_wipe(scalar_copy, sizeof scalar_copy);
    gsec_wipe(&d, sizeof d);
    gsec_wipe(out, GSEC_ECDSA_P256_PUBLIC_LEN);
    return GSEC_ERR_INVALID;
  }
  if (!p256_scalarmult_base(&x, &y, scalar_copy)) {
    gsec_wipe(scalar_copy, sizeof scalar_copy);
    gsec_wipe(&d, sizeof d);
    gsec_wipe(out, GSEC_ECDSA_P256_PUBLIC_LEN);
    return GSEC_ERR_INVALID;
  }
  fe_p256_to_bytes(raw, &x);
  fe_p256_to_bytes(raw + GSEC_ECDSA_P256_LEN, &y);
  memcpy(out, raw, sizeof raw);
  gsec_wipe(scalar_copy, sizeof scalar_copy);
  gsec_wipe(&d, sizeof d);
  gsec_wipe(&x, sizeof x);
  gsec_wipe(&y, sizeof y);
  gsec_wipe(raw, sizeof raw);
  return GSEC_OK;
}

GSEC_Result gsec_ecdsa_p256_sign(const void * scalar, const void * msg,
    size_t msg_len, void * sig) {
  unsigned char scalar_copy[GSEC_ECDSA_P256_LEN];
  unsigned char h1[GSEC_SHA256_DIGEST_LEN];
  unsigned char bits[GSEC_SHA256_DIGEST_LEN];
  unsigned char V[GSEC_SHA256_DIGEST_LEN];
  unsigned char K[GSEC_SHA256_DIGEST_LEN];
  unsigned char block[GSEC_SHA256_DIGEST_LEN + 1u + GSEC_ECDSA_P256_LEN +
      GSEC_SHA256_DIGEST_LEN];
  unsigned char zero[GSEC_ECDSA_P256_LEN];
  sc_p256 d;
  sc_p256 e;
  int i;
  int attempt;
  GSEC_Result result;

  if (scalar == NULL || sig == NULL || (msg == NULL && msg_len != 0)) {
    return GSEC_ERR_INVALID;
  }
  result = gsec_sha256(msg, msg_len, h1);
  if (result != GSEC_OK) {
    gsec_wipe(h1, sizeof h1);
    gsec_wipe(sig, GSEC_ECDSA_P256_SIG_LEN);
    return result;
  }
  memcpy(scalar_copy, scalar, sizeof scalar_copy);
  if (!scalar_ok(scalar_copy, &d)) {
    gsec_wipe(scalar_copy, sizeof scalar_copy);
    gsec_wipe(&d, sizeof d);
    gsec_wipe(h1, sizeof h1);
    gsec_wipe(sig, GSEC_ECDSA_P256_SIG_LEN);
    return GSEC_ERR_INVALID;
  }
  sc_p256_reduce_bytes(&e, h1);
  sc_p256_to_bytes(bits, &e);
  for (i = 0; i < (int)sizeof V; i++) {
    V[i] = 0x01;
    K[i] = 0x00;
    zero[i] = 0;
  }
  memcpy(block, V, sizeof V);
  block[sizeof V] = 0x00;
  memcpy(block + sizeof V + 1u, scalar_copy, sizeof scalar_copy);
  memcpy(block + sizeof V + 1u + sizeof scalar_copy, bits, sizeof bits);
  result = hmac_sha256(K, block, sizeof block, K);
  if (result == GSEC_OK) {
    result = hmac_sha256(K, V, sizeof V, V);
  }
  if (result == GSEC_OK) {
    memcpy(block, V, sizeof V);
    block[sizeof V] = 0x01;
    result = hmac_sha256(K, block, sizeof block, K);
  }
  if (result == GSEC_OK) {
    result = hmac_sha256(K, V, sizeof V, V);
  }
  if (result != GSEC_OK) {
    gsec_wipe(scalar_copy, sizeof scalar_copy);
    gsec_wipe(&d, sizeof d);
    gsec_wipe(&e, sizeof e);
    gsec_wipe(h1, sizeof h1);
    gsec_wipe(bits, sizeof bits);
    gsec_wipe(V, sizeof V);
    gsec_wipe(K, sizeof K);
    gsec_wipe(block, sizeof block);
    gsec_wipe(sig, GSEC_ECDSA_P256_SIG_LEN);
    return result;
  }
  for (attempt = 0; attempt < 8; attempt++) {
    unsigned char T[GSEC_SHA256_DIGEST_LEN];
    unsigned char rb[GSEC_ECDSA_P256_LEN];
    unsigned char sb[GSEC_ECDSA_P256_LEN];
    unsigned char xb[GSEC_ECDSA_P256_LEN];
    sc_p256 k;
    sc_p256 r;
    sc_p256 s;
    sc_p256 rd;
    sc_p256 sum;
    sc_p256 kinv;
    sc_p256 neg;
    p256_point base;
    p256_point R;
    fe_p256 x;
    fe_p256 y;
    int k_ok;
    int r_ok;
    int s_ok;

    result = hmac_sha256(K, V, sizeof V, V);
    if (result != GSEC_OK) {
      break;
    }
    memcpy(T, V, sizeof T);
    sc_p256_set_bytes(&k, T);
    sc_p256_to_bytes(rb, &k);
    k_ok = publish(sc_p256_lt_n(&k)) &&
        gsec_equal(rb, zero, sizeof zero) != GSEC_OK;
    r_ok = 0;
    s_ok = 0;
    if (k_ok) {
      p256_point_base(&base);
      p256_scalarmult_proj(&R, T, &base);
      if (p256_point_affine(&x, &y, &R)) {
        fe_p256_to_bytes(xb, &x);
        sc_p256_reduce_bytes(&r, xb);
        sc_p256_to_bytes(rb, &r);
        r_ok = gsec_equal(rb, zero, sizeof zero) != GSEC_OK;
      }
    }
    if (k_ok && r_ok) {
      sc_p256_mul(&rd, &r, &d);
      sc_p256_add(&sum, &e, &rd);
      sc_p256_inv(&kinv, &k);
      sc_p256_mul(&s, &kinv, &sum);
      sc_p256_to_bytes(sb, &s);
      s_ok = gsec_equal(sb, zero, sizeof zero) != GSEC_OK;
      if (s_ok) {
        memset(&neg, 0, sizeof neg);
        sc_p256_sub(&neg, &neg, &s);
        sc_p256_cmov(&s, &neg, sc_p256_gt_half(&s));
        sc_p256_to_bytes(sb, &s);
        memcpy(sig, rb, sizeof rb);
        memcpy((unsigned char *)sig + sizeof rb, sb, sizeof sb);
      }
    }
    gsec_wipe(T, sizeof T);
    gsec_wipe(xb, sizeof xb);
    gsec_wipe(&k, sizeof k);
    gsec_wipe(&r, sizeof r);
    gsec_wipe(&s, sizeof s);
    gsec_wipe(&rd, sizeof rd);
    gsec_wipe(&sum, sizeof sum);
    gsec_wipe(&kinv, sizeof kinv);
    gsec_wipe(&neg, sizeof neg);
    gsec_wipe(&base, sizeof base);
    gsec_wipe(&R, sizeof R);
    gsec_wipe(&x, sizeof x);
    gsec_wipe(&y, sizeof y);
    if (result == GSEC_OK && k_ok && r_ok && s_ok) {
      gsec_wipe(rb, sizeof rb);
      gsec_wipe(sb, sizeof sb);
      gsec_wipe(scalar_copy, sizeof scalar_copy);
      gsec_wipe(&d, sizeof d);
      gsec_wipe(&e, sizeof e);
      gsec_wipe(h1, sizeof h1);
      gsec_wipe(bits, sizeof bits);
      gsec_wipe(V, sizeof V);
      gsec_wipe(K, sizeof K);
      gsec_wipe(block, sizeof block);
      gsec_wipe(zero, sizeof zero);
      return GSEC_OK;
    }
    gsec_wipe(rb, sizeof rb);
    gsec_wipe(sb, sizeof sb);
    memcpy(block, V, sizeof V);
    block[sizeof V] = 0x00;
    result = hmac_sha256(K, block, sizeof V + 1u, K);
    if (result == GSEC_OK) {
      result = hmac_sha256(K, V, sizeof V, V);
    }
    if (result != GSEC_OK) {
      break;
    }
  }
  gsec_wipe(scalar_copy, sizeof scalar_copy);
  gsec_wipe(&d, sizeof d);
  gsec_wipe(&e, sizeof e);
  gsec_wipe(h1, sizeof h1);
  gsec_wipe(bits, sizeof bits);
  gsec_wipe(V, sizeof V);
  gsec_wipe(K, sizeof K);
  gsec_wipe(block, sizeof block);
  gsec_wipe(zero, sizeof zero);
  gsec_wipe(sig, GSEC_ECDSA_P256_SIG_LEN);
  if (result != GSEC_OK) {
    return result;
  }
  return GSEC_ERR_INTERNAL;
}

GSEC_Result gsec_ecdsa_p256_verify(const void * pub, const void * msg,
    size_t msg_len, const void * sig) {
  unsigned char h1[GSEC_SHA256_DIGEST_LEN];
  unsigned char u1b[GSEC_ECDSA_P256_LEN];
  unsigned char u2b[GSEC_ECDSA_P256_LEN];
  unsigned char xb[GSEC_ECDSA_P256_LEN];
  unsigned char rb[GSEC_ECDSA_P256_LEN];
  unsigned char zero[GSEC_ECDSA_P256_LEN];
  sc_p256 e;
  sc_p256 r;
  sc_p256 s;
  sc_p256 w;
  sc_p256 u1;
  sc_p256 u2;
  sc_p256 rx;
  p256_point base;
  p256_point Q;
  p256_point p1;
  p256_point p2;
  p256_point sum;
  fe_p256 x;
  fe_p256 y;
  int i;
  int match;
  GSEC_Result result;

  if (pub == NULL || sig == NULL || (msg == NULL && msg_len != 0)) {
    return GSEC_ERR_INVALID;
  }
  result = gsec_sha256(msg, msg_len, h1);
  if (result != GSEC_OK) {
    gsec_wipe(h1, sizeof h1);
    return result;
  }
  for (i = 0; i < (int)sizeof zero; i++) {
    zero[i] = 0;
  }
  sc_p256_set_bytes(&r, sig);
  sc_p256_set_bytes(&s, (const unsigned char *)sig + GSEC_ECDSA_P256_LEN);
  sc_p256_to_bytes(rb, &r);
  sc_p256_to_bytes(xb, &s);
  if (!sc_p256_lt_n(&r) || !sc_p256_lt_n(&s) ||
      gsec_equal(rb, zero, sizeof zero) == GSEC_OK ||
      gsec_equal(xb, zero, sizeof zero) == GSEC_OK ||
      !p256_point_decode(&Q, pub)) {
    gsec_wipe(h1, sizeof h1);
    gsec_wipe(&r, sizeof r);
    gsec_wipe(&s, sizeof s);
    gsec_wipe(&Q, sizeof Q);
    gsec_wipe(rb, sizeof rb);
    gsec_wipe(xb, sizeof xb);
    gsec_wipe(zero, sizeof zero);
    return GSEC_ERR_MISMATCH;
  }
  sc_p256_reduce_bytes(&e, h1);
  sc_p256_inv(&w, &s);
  sc_p256_mul(&u1, &e, &w);
  sc_p256_mul(&u2, &r, &w);
  sc_p256_to_bytes(u1b, &u1);
  sc_p256_to_bytes(u2b, &u2);
  p256_point_base(&base);
  p256_scalarmult_proj(&p1, u1b, &base);
  p256_scalarmult_proj(&p2, u2b, &Q);
  p256_point_add(&sum, &p1, &p2);
  if (!p256_point_affine(&x, &y, &sum)) {
    gsec_wipe(h1, sizeof h1);
    gsec_wipe(&e, sizeof e);
    gsec_wipe(&r, sizeof r);
    gsec_wipe(&s, sizeof s);
    gsec_wipe(&w, sizeof w);
    gsec_wipe(&u1, sizeof u1);
    gsec_wipe(&u2, sizeof u2);
    gsec_wipe(&base, sizeof base);
    gsec_wipe(&Q, sizeof Q);
    gsec_wipe(&p1, sizeof p1);
    gsec_wipe(&p2, sizeof p2);
    gsec_wipe(&sum, sizeof sum);
    gsec_wipe(u1b, sizeof u1b);
    gsec_wipe(u2b, sizeof u2b);
    gsec_wipe(rb, sizeof rb);
    gsec_wipe(xb, sizeof xb);
    gsec_wipe(zero, sizeof zero);
    return GSEC_ERR_MISMATCH;
  }
  fe_p256_to_bytes(xb, &x);
  sc_p256_reduce_bytes(&rx, xb);
  sc_p256_to_bytes(xb, &rx);
  match = gsec_equal(xb, rb, sizeof xb) == GSEC_OK;
  gsec_wipe(h1, sizeof h1);
  gsec_wipe(&e, sizeof e);
  gsec_wipe(&r, sizeof r);
  gsec_wipe(&s, sizeof s);
  gsec_wipe(&w, sizeof w);
  gsec_wipe(&u1, sizeof u1);
  gsec_wipe(&u2, sizeof u2);
  gsec_wipe(&rx, sizeof rx);
  gsec_wipe(&base, sizeof base);
  gsec_wipe(&Q, sizeof Q);
  gsec_wipe(&p1, sizeof p1);
  gsec_wipe(&p2, sizeof p2);
  gsec_wipe(&sum, sizeof sum);
  gsec_wipe(&x, sizeof x);
  gsec_wipe(&y, sizeof y);
  gsec_wipe(u1b, sizeof u1b);
  gsec_wipe(u2b, sizeof u2b);
  gsec_wipe(xb, sizeof xb);
  gsec_wipe(rb, sizeof rb);
  gsec_wipe(zero, sizeof zero);
  return match ? GSEC_OK : GSEC_ERR_MISMATCH;
}
