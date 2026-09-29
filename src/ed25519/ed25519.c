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
 * Pure Ed25519. Points are extended twisted Edwards coordinates with
 * a = −1, added by the complete formula, so the identity needs no
 * special case. A secret scalar selects the sum with a mask. Reduction
 * modulo the group order walks every bit of the input and subtracts
 * with a mask.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/ed25519.h>
#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/sha512.h>

#include "../curve25519/fe25519.h"

#include <string.h>

typedef struct {
  fe25519 x;
  fe25519 y;
  fe25519 z;
  fe25519 t;
} ge;

typedef struct {
  uint64_t v[4];
} sc;

/* d = −121665/121666 mod p, and twice that. The addition formula uses 2d. */
static const int64_t FE_D[16] = {
  30883, 4953, 19914, 30187, 55467, 16705, 2637, 112,
  59544, 30585, 16505, 36039, 65139, 11119, 27886, 20995
};

static const int64_t FE_D2[16] = {
  61785, 9906, 39828, 60374, 45398, 33411, 5274, 224,
  53552, 61171, 33010, 6542, 64743, 22239, 55772, 9222
};

/* 2^((p−1)/4) mod p, a square root of −1. */
static const int64_t FE_I[16] = {
  41136, 18958, 6951, 50414, 58488, 44335, 6150, 12099,
  55207, 15867, 153, 11085, 57099, 20417, 9344, 11139
};

static const int64_t FE_BX[16] = {
  54554, 36645, 11616, 51542, 42930, 38181, 51040, 26924,
  56412, 64982, 57905, 49316, 21502, 52590, 14035, 8553
};

static const int64_t FE_BY[16] = {
  26200, 26214, 26214, 26214, 26214, 26214, 26214, 26214,
  26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214
};

/* Group order, little-endian uint64 limbs. */
static const uint64_t SC_L[4] = {
  UINT64_C(0x5812631a5cf5d3ed),
  UINT64_C(0x14def9dea2f79cd6),
  UINT64_C(0x0000000000000000),
  UINT64_C(0x1000000000000000)
};

static const unsigned char SC_L_BYTES[32] = {
  0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
  0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static void fe_clear(fe25519 o) {
  int i;

  for (i = 0; i < 16; i++) {
    o[i] = 0;
  }
}

static void fe_copy_limbs(fe25519 o, const int64_t in[16]) {
  int i;

  for (i = 0; i < 16; i++) {
    o[i] = in[i];
  }
}

static void ge_wipe(ge * p) {
  gsec_wipe(p, sizeof *p);
}

static void ge_base(ge * p) {
  fe_clear(p->z);
  fe_copy_limbs(p->x, FE_BX);
  fe_copy_limbs(p->y, FE_BY);
  p->z[0] = 1;
  fe25519_mul(p->t, p->x, p->y);
}

static void ge_add(ge * o, const ge * p, const ge * q) {
  fe25519 a;
  fe25519 b;
  fe25519 c;
  fe25519 d;
  fe25519 e;
  fe25519 f;
  fe25519 g;
  fe25519 h;
  fe25519 t1;
  fe25519 t2;

  fe25519_sub(t1, p->y, p->x);
  fe25519_sub(t2, q->y, q->x);
  fe25519_mul(a, t1, t2);
  fe25519_add(t1, p->y, p->x);
  fe25519_add(t2, q->y, q->x);
  fe25519_mul(b, t1, t2);
  fe25519_mul(t1, p->t, q->t);
  fe25519_mul(c, t1, FE_D2);
  fe25519_mul(t1, p->z, q->z);
  fe25519_add(d, t1, t1);
  fe25519_sub(e, b, a);
  fe25519_sub(f, d, c);
  fe25519_add(g, d, c);
  fe25519_add(h, b, a);
  fe25519_mul(o->x, e, f);
  fe25519_mul(o->y, g, h);
  fe25519_mul(o->t, e, h);
  fe25519_mul(o->z, f, g);
  gsec_wipe(a, sizeof a);
  gsec_wipe(b, sizeof b);
  gsec_wipe(c, sizeof c);
  gsec_wipe(d, sizeof d);
  gsec_wipe(e, sizeof e);
  gsec_wipe(f, sizeof f);
  gsec_wipe(g, sizeof g);
  gsec_wipe(h, sizeof h);
  gsec_wipe(t1, sizeof t1);
  gsec_wipe(t2, sizeof t2);
}

static void ge_cmov(ge * o, const ge * a, int bit) {
  fe25519_cmov(o->x, a->x, bit);
  fe25519_cmov(o->y, a->y, bit);
  fe25519_cmov(o->z, a->z, bit);
  fe25519_cmov(o->t, a->t, bit);
}

static void ge_scalarmult(ge * o, const unsigned char scalar[32], const ge * base) {
  ge r;
  ge q;
  ge sum;
  int i;

  q = *base;
  fe_clear(r.x);
  fe_clear(r.y);
  fe_clear(r.z);
  fe_clear(r.t);
  r.y[0] = 1;
  r.z[0] = 1;
  for (i = 0; i < 256; i++) {
    int bit = (scalar[i >> 3] >> (i & 7)) & 1;

    ge_add(&sum, &r, &q);
    ge_cmov(&r, &sum, bit);
    ge_add(&q, &q, &q);
  }
  *o = r;
  ge_wipe(&q);
  ge_wipe(&sum);
  ge_wipe(&r);
}

static void ge_encode(unsigned char out[32], const ge * p) {
  fe25519 zinv;
  fe25519 x;
  fe25519 y;
  unsigned char xb[32];

  fe25519_invert(zinv, p->z);
  fe25519_mul(x, p->x, zinv);
  fe25519_mul(y, p->y, zinv);
  fe25519_to_bytes(out, y);
  fe25519_to_bytes(xb, x);
  out[31] = (unsigned char)(out[31] | ((xb[0] & 1u) << 7));
  gsec_wipe(zinv, sizeof zinv);
  gsec_wipe(x, sizeof x);
  gsec_wipe(y, sizeof y);
  gsec_wipe(xb, sizeof xb);
}

/* z^(2^252 − 3). The skipped bit is the public exponent. */
static void fe_pow_pm5_8(fe25519 o, const fe25519 z) {
  int i;

  for (i = 0; i < 16; i++) {
    o[i] = z[i];
  }
  for (i = 250; i >= 0; i--) {
    fe25519_sq(o, o);
    if (i != 1) {
      fe25519_mul(o, o, z);
    }
  }
}

static int bytes_equal(const unsigned char * a, const unsigned char * b, size_t n) {
  return gsec_equal(a, b, n) == GSEC_OK;
}

/* y is the low 255 bits. It is public here: this is a signature check. */
static int y_canonical(const unsigned char s[32]) {
  static const unsigned char prime[32] = {
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
  };
  unsigned char y[32];
  int i;

  memcpy(y, s, 32);
  y[31] = (unsigned char)(y[31] & 0x7fu);
  for (i = 31; i >= 0; i--) {
    if (y[i] > prime[i]) {
      return 0;
    }
    if (y[i] < prime[i]) {
      return 1;
    }
  }
  return 0;
}

static int ge_decode(ge * p, const unsigned char s[32]) {
  fe25519 u;
  fe25519 v;
  fe25519 v3;
  fe25519 v7;
  fe25519 uv7;
  fe25519 pow;
  fe25519 x;
  fe25519 t;
  fe25519 neg;
  fe25519 zero;
  unsigned char xb[32];
  unsigned char ub[32];
  unsigned char tb[32];
  unsigned sign;
  int i;
  int is_zero;
  int ok;

  if (!y_canonical(s)) {
    return 0;
  }
  sign = (unsigned)(s[31] >> 7);
  fe_clear(p->x);
  fe_clear(p->y);
  fe_clear(p->z);
  fe_clear(p->t);
  fe_clear(neg);
  fe_clear(zero);
  fe25519_from_bytes(p->y, s);
  p->z[0] = 1;
  fe25519_sq(u, p->y);
  fe25519_sub(u, u, p->z);
  fe25519_sq(v, p->y);
  fe25519_mul(v, v, FE_D);
  fe25519_add(v, v, p->z);
  fe25519_sq(t, v);
  fe25519_mul(v3, t, v);
  fe25519_sq(t, v3);
  fe25519_mul(v7, t, v);
  fe25519_mul(uv7, u, v7);
  fe_pow_pm5_8(pow, uv7);
  fe25519_mul(t, u, v3);
  fe25519_mul(x, t, pow);
  fe25519_sq(t, x);
  fe25519_mul(t, t, v);
  fe25519_to_bytes(tb, t);
  fe25519_to_bytes(ub, u);
  ok = 1;
  if (!bytes_equal(tb, ub, 32)) {
    fe25519_sub(neg, zero, u);
    fe25519_to_bytes(ub, neg);
    if (!bytes_equal(tb, ub, 32)) {
      ok = 0;
    } else {
      fe25519_mul(x, x, FE_I);
    }
  }
  if (ok) {
    fe25519_to_bytes(xb, x);
    is_zero = 1;
    for (i = 0; i < 32; i++) {
      if (xb[i] != 0) {
        is_zero = 0;
      }
    }
    if (is_zero && sign == 1u) {
      ok = 0;
    } else if ((unsigned)(xb[0] & 1u) != sign) {
      fe25519_sub(x, zero, x);
    }
  }
  if (ok) {
    fe25519_mul(p->t, x, p->y);
    for (i = 0; i < 16; i++) {
      p->x[i] = x[i];
    }
  }
  gsec_wipe(u, sizeof u);
  gsec_wipe(v, sizeof v);
  gsec_wipe(v3, sizeof v3);
  gsec_wipe(v7, sizeof v7);
  gsec_wipe(uv7, sizeof uv7);
  gsec_wipe(pow, sizeof pow);
  gsec_wipe(x, sizeof x);
  gsec_wipe(t, sizeof t);
  gsec_wipe(neg, sizeof neg);
  gsec_wipe(zero, sizeof zero);
  gsec_wipe(xb, sizeof xb);
  gsec_wipe(ub, sizeof ub);
  gsec_wipe(tb, sizeof tb);
  return ok;
}

static void sc_shl1(sc * r, unsigned bit) {
  uint64_t carry = bit;
  int i;

  for (i = 0; i < 4; i++) {
    uint64_t next = r->v[i] >> 63;

    r->v[i] = (r->v[i] << 1) | carry;
    carry = next;
  }
}

static void sc_csub_l(sc * r) {
  uint64_t tmp[4];
  uint64_t borrow = 0;
  uint64_t mask;
  int i;

  for (i = 0; i < 4; i++) {
    uint64_t t = r->v[i] - borrow;
    uint64_t br1 = (uint64_t)(t > r->v[i]);
    uint64_t d = t - SC_L[i];
    uint64_t br2 = (uint64_t)(d > t);

    tmp[i] = d;
    borrow = br1 | br2;
  }
  mask = (uint64_t)0 - (borrow ^ UINT64_C(1));
  for (i = 0; i < 4; i++) {
    r->v[i] ^= mask & (r->v[i] ^ tmp[i]);
  }
}

static void sc_reduce(sc * o, const unsigned char wide[64]) {
  int i;

  memset(o, 0, sizeof *o);
  for (i = 511; i >= 0; i--) {
    unsigned bit = ((unsigned)wide[i >> 3] >> (i & 7)) & 1u;

    sc_shl1(o, bit);
    sc_csub_l(o);
  }
}

static void sc_load(sc * o, const unsigned char s[32]) {
  int i;
  int b;

  for (i = 0; i < 4; i++) {
    uint64_t v = 0;

    for (b = 0; b < 8; b++) {
      v |= (uint64_t)s[i * 8 + b] << (8 * b);
    }
    o->v[i] = v;
  }
}

static void sc_store(unsigned char out[32], const sc * a) {
  int i;
  int b;

  for (i = 0; i < 4; i++) {
    for (b = 0; b < 8; b++) {
      out[i * 8 + b] = (unsigned char)(a->v[i] >> (8 * b));
    }
  }
}

static void sc_mul(sc * o, const sc * a, const sc * b) {
  uint32_t aa[8];
  uint32_t bb[8];
  uint32_t acc[16];
  unsigned char wide[64];
  int i;
  int j;

  for (i = 0; i < 4; i++) {
    aa[i * 2] = (uint32_t)a->v[i];
    aa[i * 2 + 1] = (uint32_t)(a->v[i] >> 32);
    bb[i * 2] = (uint32_t)b->v[i];
    bb[i * 2 + 1] = (uint32_t)(b->v[i] >> 32);
  }
  for (i = 0; i < 16; i++) {
    acc[i] = 0;
  }
  for (i = 0; i < 8; i++) {
    uint64_t carry = 0;

    for (j = 0; j < 8; j++) {
      uint64_t p = (uint64_t)aa[i] * (uint64_t)bb[j] + acc[i + j] + carry;

      acc[i + j] = (uint32_t)p;
      carry = p >> 32;
    }
    acc[i + 8] = (uint32_t)carry;
  }
  for (i = 0; i < 16; i++) {
    wide[i * 4] = (unsigned char)acc[i];
    wide[i * 4 + 1] = (unsigned char)(acc[i] >> 8);
    wide[i * 4 + 2] = (unsigned char)(acc[i] >> 16);
    wide[i * 4 + 3] = (unsigned char)(acc[i] >> 24);
  }
  sc_reduce(o, wide);
  gsec_wipe(aa, sizeof aa);
  gsec_wipe(bb, sizeof bb);
  gsec_wipe(acc, sizeof acc);
  gsec_wipe(wide, sizeof wide);
}

static void sc_add(sc * o, const sc * a, const sc * b) {
  uint64_t carry = 0;
  int i;

  for (i = 0; i < 4; i++) {
    uint64_t sum = a->v[i] + b->v[i];
    uint64_t c1 = (uint64_t)(sum < a->v[i]);
    uint64_t sum2 = sum + carry;
    uint64_t c2 = (uint64_t)(sum2 < sum);

    o->v[i] = sum2;
    carry = c1 | c2;
  }
  sc_csub_l(o);
}

static int sc_canonical(const unsigned char s[32]) {
  int i;

  for (i = 31; i >= 0; i--) {
    if (s[i] < SC_L_BYTES[i]) {
      return 1;
    }
    if (s[i] > SC_L_BYTES[i]) {
      return 0;
    }
  }
  return 0;
}

static void clamp(unsigned char a[32], const unsigned char h[32]) {
  int i;

  for (i = 0; i < 32; i++) {
    a[i] = h[i];
  }
  a[0] = (unsigned char)(a[0] & 248u);
  a[31] = (unsigned char)(a[31] & 63u);
  a[31] = (unsigned char)(a[31] | 64u);
}

static GSEC_Result hash_update(GSEC_Sha512 * ctx, const void * data, size_t n) {
  if (n == 0) {
    return GSEC_OK;
  }
  return gsec_sha512_update(ctx, data, n);
}

static GSEC_Result hash_dom(const unsigned char * dom, size_t dom_n,
    const unsigned char * a, size_t an, const unsigned char * b, size_t bn,
    const void * c, size_t cn, unsigned char out[GSEC_SHA512_DIGEST_LEN]) {
  GSEC_Sha512 ctx;
  GSEC_Result result;

  result = gsec_sha512_init(&ctx);
  if (result != GSEC_OK) {
    return result;
  }
  result = hash_update(&ctx, dom, dom_n);
  if (result != GSEC_OK) {
    return result;
  }
  result = hash_update(&ctx, a, an);
  if (result != GSEC_OK) {
    return result;
  }
  result = hash_update(&ctx, b, bn);
  if (result != GSEC_OK) {
    return result;
  }
  result = hash_update(&ctx, c, cn);
  if (result != GSEC_OK) {
    return result;
  }
  return gsec_sha512_final(&ctx, out);
}

static size_t domain(unsigned char * out, int phflag, const void * ctx,
    size_t ctx_len) {
  static const char prefix[] = "SigEd25519 no Ed25519 collisions";

  if (phflag < 0) {
    return 0;
  }
  memcpy(out, prefix, 32);
  out[32] = (unsigned char)phflag;
  out[33] = (unsigned char)ctx_len;
  if (ctx_len != 0) {
    memcpy(out + 34, ctx, ctx_len);
  }
  return 34u + ctx_len;
}

static void public_from_scalar(unsigned char out[32], const unsigned char scalar[32]) {
  ge base;
  ge p;

  ge_base(&base);
  ge_scalarmult(&p, scalar, &base);
  ge_encode(out, &p);
  ge_wipe(&base);
  ge_wipe(&p);
}

GSEC_Result gsec_ed25519_public(const void * seed, void * out) {
  unsigned char seed_copy[GSEC_ED25519_LEN];
  unsigned char hash[GSEC_SHA512_DIGEST_LEN];
  unsigned char scalar[GSEC_ED25519_LEN];
  unsigned char raw[GSEC_ED25519_LEN];
  GSEC_Result result;

  if (seed == NULL || out == NULL) {
    return GSEC_ERR_INVALID;
  }
  memcpy(seed_copy, seed, GSEC_ED25519_LEN);
  result = gsec_sha512(seed_copy, GSEC_ED25519_LEN, hash);
  gsec_wipe(seed_copy, sizeof seed_copy);
  if (result != GSEC_OK) {
    gsec_wipe(hash, sizeof hash);
    return result;
  }
  clamp(scalar, hash);
  gsec_wipe(hash, sizeof hash);
  public_from_scalar(raw, scalar);
  gsec_wipe(scalar, sizeof scalar);
  memcpy(out, raw, GSEC_ED25519_LEN);
  gsec_wipe(raw, sizeof raw);
  return GSEC_OK;
}

static GSEC_Result sign_variant(const void * seed, const void * data, size_t n,
    void * out, int phflag, const void * ctx, size_t ctx_len) {
  unsigned char seed_copy[GSEC_ED25519_LEN];
  unsigned char hash[GSEC_SHA512_DIGEST_LEN];
  unsigned char scalar[GSEC_ED25519_LEN];
  unsigned char prefix[32];
  unsigned char pub[GSEC_ED25519_LEN];
  unsigned char rhash[GSEC_SHA512_DIGEST_LEN];
  unsigned char khash[GSEC_SHA512_DIGEST_LEN];
  unsigned char rbytes[32];
  unsigned char sbytes[32];
  unsigned char sig[GSEC_ED25519_SIG_LEN];
  sc r;
  sc k;
  sc a;
  sc ka;
  sc s;
  unsigned char dom[34 + 255];
  unsigned char ph[GSEC_SHA512_DIGEST_LEN];
  const unsigned char * body;
  size_t body_n;
  size_t dom_n;
  GSEC_Result result;
  const unsigned char * message = (const unsigned char *)data;

  if (seed == NULL || out == NULL || (data == NULL && n != 0) ||
      ctx_len > 255 || (ctx == NULL && ctx_len != 0)) {
    return GSEC_ERR_INVALID;
  }
  memcpy(seed_copy, seed, GSEC_ED25519_LEN);
  result = gsec_sha512(seed_copy, GSEC_ED25519_LEN, hash);
  gsec_wipe(seed_copy, sizeof seed_copy);
  if (result != GSEC_OK) {
    gsec_wipe(hash, sizeof hash);
    return result;
  }
  clamp(scalar, hash);
  memcpy(prefix, hash + 32, 32);
  gsec_wipe(hash, sizeof hash);
  public_from_scalar(pub, scalar);
  if (phflag > 0) {
    result = gsec_sha512(message, n, ph);
    if (result != GSEC_OK) {
      gsec_wipe(prefix, sizeof prefix);
      gsec_wipe(scalar, sizeof scalar);
      gsec_wipe(pub, sizeof pub);
      return result;
    }
    body = ph;
    body_n = GSEC_SHA512_DIGEST_LEN;
  } else {
    body = message;
    body_n = n;
  }
  dom_n = domain(dom, phflag, ctx, ctx_len);
  result = hash_dom(dom, dom_n, prefix, 32, body, body_n, NULL, 0, rhash);
  if (result != GSEC_OK) {
    gsec_wipe(prefix, sizeof prefix);
    gsec_wipe(scalar, sizeof scalar);
    gsec_wipe(pub, sizeof pub);
    gsec_wipe(rhash, sizeof rhash);
    return result;
  }
  sc_reduce(&r, rhash);
  gsec_wipe(rhash, sizeof rhash);
  sc_store(rbytes, &r);
  public_from_scalar(sig, rbytes);
  result = hash_dom(dom, dom_n, sig, 32, pub, 32, body, body_n, khash);
  if (result != GSEC_OK) {
    gsec_wipe(prefix, sizeof prefix);
    gsec_wipe(scalar, sizeof scalar);
    gsec_wipe(pub, sizeof pub);
    gsec_wipe(rbytes, sizeof rbytes);
    gsec_wipe(sig, sizeof sig);
    gsec_wipe(khash, sizeof khash);
    gsec_wipe(&r, sizeof r);
    return result;
  }
  sc_reduce(&k, khash);
  gsec_wipe(khash, sizeof khash);
  sc_load(&a, scalar);
  sc_mul(&ka, &k, &a);
  sc_add(&s, &r, &ka);
  sc_store(sbytes, &s);
  memcpy(sig + 32, sbytes, 32);
  memcpy(out, sig, GSEC_ED25519_SIG_LEN);
  gsec_wipe(prefix, sizeof prefix);
  gsec_wipe(scalar, sizeof scalar);
  gsec_wipe(pub, sizeof pub);
  gsec_wipe(rbytes, sizeof rbytes);
  gsec_wipe(sbytes, sizeof sbytes);
  gsec_wipe(sig, sizeof sig);
  gsec_wipe(&r, sizeof r);
  gsec_wipe(&k, sizeof k);
  gsec_wipe(&a, sizeof a);
  gsec_wipe(&ka, sizeof ka);
  gsec_wipe(&s, sizeof s);
  gsec_wipe(dom, sizeof dom);
  gsec_wipe(ph, sizeof ph);
  return GSEC_OK;
}

GSEC_Result gsec_ed25519_sign(const void * seed, const void * data, size_t n,
    void * out) {
  return sign_variant(seed, data, n, out, -1, NULL, 0);
}

GSEC_Result gsec_ed25519_ctx_sign(const void * seed, const void * data,
    size_t n, const void * ctx, size_t ctx_len, void * out) {
  return sign_variant(seed, data, n, out, 0, ctx, ctx_len);
}

GSEC_Result gsec_ed25519_ph_sign(const void * seed, const void * data,
    size_t n, const void * ctx, size_t ctx_len, void * out) {
  return sign_variant(seed, data, n, out, 1, ctx, ctx_len);
}

static GSEC_Result verify_variant(const void * public_key, const void * data,
    size_t n, const void * sig, int phflag, const void * ctx, size_t ctx_len) {
  const unsigned char * pub = (const unsigned char *)public_key;
  const unsigned char * signature = (const unsigned char *)sig;
  const unsigned char * message = (const unsigned char *)data;
  unsigned char khash[GSEC_SHA512_DIGEST_LEN];
  unsigned char kbytes[32];
  unsigned char lhs[32];
  ge base;
  ge point_a;
  ge point_r;
  ge sb;
  ge ka;
  ge neg;
  ge sum;
  fe25519 zero;
  sc k;
  unsigned char dom[34 + 255];
  unsigned char ph[GSEC_SHA512_DIGEST_LEN];
  const unsigned char * body;
  size_t body_n;
  size_t dom_n;
  GSEC_Result result;

  if (public_key == NULL || sig == NULL || (data == NULL && n != 0) ||
      ctx_len > 255 || (ctx == NULL && ctx_len != 0)) {
    return GSEC_ERR_INVALID;
  }
  /* Not a well-formed encoding is GSEC_ERR_INVALID, and a well-formed one
   * that does not verify is GSEC_ERR_MISMATCH. Both are refusals, and the
   * split is deliberate: S at or above the group order and a y coordinate at
   * or above the field prime are RFC 8032 section 5.1.7 and 5.1.3 rejections
   * of the *bytes*, not statements about the signature, and a caller wants to
   * be able to tell a peer that sent garbage from one whose signature is
   * wrong. It also makes the checks testable - with every rejection funnelled
   * into one code, removing the non-canonical-y check changed no answer that
   * any test could see, which is exactly how it survived mutation. All three
   * inputs here are public, so distinguishing them leaks nothing. */
  if (!sc_canonical(signature + 32) || !ge_decode(&point_a, pub) ||
      !ge_decode(&point_r, signature)) {
    return GSEC_ERR_INVALID;
  }
  if (phflag > 0) {
    result = gsec_sha512(message, n, ph);
    if (result != GSEC_OK) {
      return result;
    }
    body = ph;
    body_n = GSEC_SHA512_DIGEST_LEN;
  } else {
    body = message;
    body_n = n;
  }
  dom_n = domain(dom, phflag, ctx, ctx_len);
  result = hash_dom(dom, dom_n, signature, 32, pub, 32, body, body_n, khash);
  if (result != GSEC_OK) {
    return result;
  }
  sc_reduce(&k, khash);
  gsec_wipe(khash, sizeof khash);
  sc_store(kbytes, &k);
  ge_base(&base);
  ge_scalarmult(&sb, signature + 32, &base);
  ge_scalarmult(&ka, kbytes, &point_a);
  fe_clear(zero);
  fe25519_sub(neg.x, zero, ka.x);
  fe25519_sub(neg.t, zero, ka.t);
  memcpy(neg.y, ka.y, sizeof neg.y);
  memcpy(neg.z, ka.z, sizeof neg.z);
  /* [S]B = R + [k]A, so [S]B − [k]A recovers R. */
  ge_add(&sum, &sb, &neg);
  ge_encode(lhs, &sum);
  result = gsec_equal(lhs, signature, 32);
  ge_wipe(&base);
  ge_wipe(&point_a);
  ge_wipe(&point_r);
  ge_wipe(&sb);
  ge_wipe(&ka);
  ge_wipe(&neg);
  ge_wipe(&sum);
  gsec_wipe(kbytes, sizeof kbytes);
  gsec_wipe(&k, sizeof k);
  gsec_wipe(lhs, sizeof lhs);
  gsec_wipe(dom, sizeof dom);
  gsec_wipe(ph, sizeof ph);
  return result;
}

GSEC_Result gsec_ed25519_verify(const void * public_key, const void * data,
    size_t n, const void * sig) {
  return verify_variant(public_key, data, n, sig, -1, NULL, 0);
}

GSEC_Result gsec_ed25519_ctx_verify(const void * public_key, const void * data,
    size_t n, const void * sig, const void * ctx, size_t ctx_len) {
  return verify_variant(public_key, data, n, sig, 0, ctx, ctx_len);
}

GSEC_Result gsec_ed25519_ph_verify(const void * public_key, const void * data,
    size_t n, const void * sig, const void * ctx, size_t ctx_len) {
  return verify_variant(public_key, data, n, sig, 1, ctx, ctx_len);
}
