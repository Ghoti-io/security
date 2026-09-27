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
 * Montgomery multiplication modulo an odd modulus. One subtraction
 * finishes each product, selected with a mask. bn_modexp walks a public
 * exponent from the high bit and skips the leading zeros. bn_modexp_ct
 * walks every bit of the modulus width, squares, multiplies, and keeps
 * one of the two with a mask.
 */

#include "bn.h"

#include <ghoti.io/security/secret.h>

#include <string.h>

int bn_limbs_for(size_t nbytes) {
  return (int)((nbytes + 3u) / 4u);
}

int bn_from_be(bn * o, const unsigned char * p, size_t n) {
  size_t i;

  if (bn_limbs_for(n) > BN_LIMBS) {
    return 0;
  }
  memset(o, 0, sizeof *o);
  o->n = bn_limbs_for(n);
  if (o->n == 0) {
    o->n = 1;
  }
  for (i = 0; i < n; i++) {
    size_t from_end = n - 1u - i;

    o->v[from_end / 4u] |= (uint32_t)p[i] << ((from_end % 4u) * 8u);
  }
  return 1;
}

void bn_to_be(unsigned char * out, size_t n, const bn * a) {
  size_t i;

  for (i = 0; i < n; i++) {
    size_t from_end = n - 1u - i;

    out[i] = (unsigned char)(a->v[from_end / 4u] >> ((from_end % 4u) * 8u));
  }
}

int bn_cmp(const bn * a, const bn * b) {
  int i;

  for (i = a->n - 1; i >= 0; i--) {
    if (a->v[i] != b->v[i]) {
      return a->v[i] > b->v[i] ? 1 : -1;
    }
  }
  return 0;
}

static void bn_cmov(bn * o, const bn * a, uint32_t bit) {
  uint32_t mask = 0u - (bit & 1u);
  int i;

  for (i = 0; i < o->n; i++) {
    o->v[i] ^= mask & (o->v[i] ^ a->v[i]);
  }
}

static uint32_t bn_sub(bn * r, const bn * a, const bn * b) {
  uint64_t borrow = 0;
  int i;

  for (i = 0; i < a->n; i++) {
    uint64_t t = (uint64_t)a->v[i] - borrow;
    uint64_t br1 = (uint64_t)(t > a->v[i]);
    uint64_t d = t - b->v[i];
    uint64_t br2 = (uint64_t)(d > t);

    r->v[i] = (uint32_t)d;
    borrow = br1 | br2;
  }
  for (; i < BN_LIMBS; i++) {
    r->v[i] = 0;
  }
  r->n = a->n;
  return (uint32_t)borrow;
}

static uint32_t bn_add(bn * r, const bn * a, const bn * b) {
  uint64_t carry = 0;
  int i;

  for (i = 0; i < a->n; i++) {
    uint64_t z = (uint64_t)a->v[i] + (uint64_t)b->v[i] + carry;

    r->v[i] = (uint32_t)z;
    carry = z >> 32;
  }
  for (; i < BN_LIMBS; i++) {
    r->v[i] = 0;
  }
  r->n = a->n;
  return (uint32_t)carry;
}

static void bn_shr1(bn * a, uint32_t hibit) {
  uint32_t carry = hibit & 1u;
  int i;

  for (i = a->n - 1; i >= 0; i--) {
    uint32_t next = a->v[i] & 1u;

    a->v[i] = (a->v[i] >> 1) | (carry << 31);
    carry = next;
  }
}

/* (x + (x odd ? n : 0)) / 2. n is odd, so the sum is even. */
static void bn_halve_mod(bn * out, const bn * x, const bn * n) {
  bn even;
  bn odd;
  uint32_t lsb = x->v[0] & 1u;
  uint32_t carry;

  even = *x;
  bn_shr1(&even, 0);
  carry = bn_add(&odd, x, n);
  bn_shr1(&odd, carry);
  *out = even;
  bn_cmov(out, &odd, lsb);
}

/* (a - b) mod n. a and b are the same width as n. */
static void bn_sub_mod(bn * r, const bn * a, const bn * b, const bn * n) {
  bn diff;
  bn sum;
  uint32_t borrow;

  borrow = bn_sub(&diff, a, b);
  (void)bn_add(&sum, &diff, n);
  *r = diff;
  bn_cmov(r, &sum, borrow);
}

static uint32_t mont_n0(uint32_t n0) {
  uint32_t x = 1;
  int i;

  for (i = 0; i < 5; i++) {
    x = (uint32_t)(x * (2u - n0 * x));
  }
  return (uint32_t)(0u - x);
}

static void mont_mul(bn * r, const bn * a, const bn * b, const bn * mod,
    uint32_t n0i) {
  uint32_t t[BN_LIMBS + 2];
  int len = mod->n;
  int i;
  int j;

  memset(t, 0, sizeof t);
  for (i = 0; i < len; i++) {
    uint64_t c = 0;
    uint32_t m;

    for (j = 0; j < len; j++) {
      uint64_t z = (uint64_t)t[j] + (uint64_t)a->v[i] * (uint64_t)b->v[j] + c;

      t[j] = (uint32_t)z;
      c = z >> 32;
    }
    {
      uint64_t z = (uint64_t)t[len] + c;

      t[len] = (uint32_t)z;
      t[len + 1] = (uint32_t)(z >> 32);
    }
    m = t[0] * n0i;
    c = 0;
    for (j = 0; j < len; j++) {
      uint64_t z = (uint64_t)t[j] + (uint64_t)m * (uint64_t)mod->v[j] + c;

      t[j] = (uint32_t)z;
      c = z >> 32;
    }
    {
      uint64_t z = (uint64_t)t[len] + c;

      t[len] = (uint32_t)z;
      t[len + 1] = (uint32_t)(t[len + 1] + (uint32_t)(z >> 32));
    }
    for (j = 0; j <= len; j++) {
      t[j] = t[j + 1];
    }
    t[len + 1] = 0;
  }
  memset(r, 0, sizeof *r);
  r->n = len;
  for (i = 0; i < len; i++) {
    r->v[i] = t[i];
  }
  {
    bn tmp;
    uint32_t extra = t[len];
    uint32_t borrow;
    uint32_t mask;

    extra |= extra >> 16;
    extra |= extra >> 8;
    extra |= extra >> 4;
    extra |= extra >> 2;
    extra |= extra >> 1;
    extra &= 1u;
    memset(&tmp, 0, sizeof tmp);
    borrow = bn_sub(&tmp, r, mod);
    /* One subtraction: the CIOS product is less than twice the modulus. */
    mask = 0u - (extra | (borrow ^ 1u));
    for (i = 0; i < len; i++) {
      r->v[i] ^= mask & (r->v[i] ^ tmp.v[i]);
    }
    gsec_wipe(&tmp, sizeof tmp);
  }
  gsec_wipe(t, sizeof t);
}

/* Double a value that is strictly less than the modulus. */
static void mod_double(bn * a, const bn * mod) {
  uint64_t c = 0;
  int i;

  for (i = 0; i < a->n; i++) {
    uint64_t z = ((uint64_t)a->v[i] << 1) + c;

    a->v[i] = (uint32_t)z;
    c = z >> 32;
  }
  if (c != 0 || bn_cmp(a, mod) >= 0) {
    bn_sub(a, a, mod);
  }
}

static void mod_pow2(bn * out, int shifts, const bn * mod) {
  int i;

  memset(out, 0, sizeof *out);
  out->n = mod->n;
  out->v[0] = 1;
  for (i = 0; i < shifts; i++) {
    mod_double(out, mod);
  }
}

int bn_modexp(bn * out, const bn * base, const unsigned char * exp, size_t exp_len,
    const bn * mod) {
  bn rr;
  bn one_m;
  bn base_m;
  bn acc;
  bn tmp;
  uint32_t n0i;
  size_t i;
  int bit;
  int started;

  if ((mod->v[0] & 1u) == 0) {
    return 0;
  }
  n0i = mont_n0(mod->v[0]);
  mod_pow2(&rr, mod->n * 64, mod);
  mod_pow2(&one_m, mod->n * 32, mod);
  mont_mul(&base_m, base, &rr, mod, n0i);
  acc = one_m;
  started = 0;
  for (i = 0; i < exp_len; i++) {
    for (bit = 7; bit >= 0; bit--) {
      int on = (exp[i] >> bit) & 1;

      if (!started) {
        if (!on) {
          continue;
        }
        started = 1;
        acc = base_m;
        continue;
      }
      mont_mul(&tmp, &acc, &acc, mod, n0i);
      acc = tmp;
      if (on) {
        mont_mul(&tmp, &acc, &base_m, mod, n0i);
        acc = tmp;
      }
    }
  }
  if (!started) {
    memset(out, 0, sizeof *out);
    out->n = mod->n;
    out->v[0] = 1;
  } else {
    memset(&tmp, 0, sizeof tmp);
    tmp.n = mod->n;
    tmp.v[0] = 1;
    mont_mul(out, &acc, &tmp, mod, n0i);
  }
  gsec_wipe(&rr, sizeof rr);
  gsec_wipe(&one_m, sizeof one_m);
  gsec_wipe(&base_m, sizeof base_m);
  gsec_wipe(&acc, sizeof acc);
  gsec_wipe(&tmp, sizeof tmp);
  return 1;
}

uint32_t bn_nonzero(const bn * a) {
  uint32_t acc = 0;
  int i;

  for (i = 0; i < a->n; i++) {
    acc |= a->v[i];
  }
  acc |= acc >> 16;
  acc |= acc >> 8;
  acc |= acc >> 4;
  acc |= acc >> 2;
  acc |= acc >> 1;
  return acc & 1u;
}

uint32_t bn_below(const bn * a, const bn * mod) {
  bn tmp;
  uint32_t borrow;

  memset(&tmp, 0, sizeof tmp);
  borrow = bn_sub(&tmp, a, mod);
  gsec_wipe(&tmp, sizeof tmp);
  return borrow & 1u;
}

void bn_reduce_ct(bn * r, const bn * mod) {
  int i;

  for (i = r->n; i < BN_LIMBS; i++) {
    r->v[i] = 0;
  }
  r->n = mod->n;
  for (i = 0; i < 256; i++) {
    bn tmp;
    uint32_t borrow;

    memset(&tmp, 0, sizeof tmp);
    borrow = bn_sub(&tmp, r, mod);
    bn_cmov(r, &tmp, borrow ^ 1u);
    gsec_wipe(&tmp, sizeof tmp);
  }
}

int bn_modmul(bn * out, const bn * a, const bn * b, const bn * mod) {
  bn rr;
  bn a_m;
  uint32_t n0i;

  if ((mod->v[0] & 1u) == 0) {
    return 0;
  }
  n0i = mont_n0(mod->v[0]);
  mod_pow2(&rr, mod->n * 64, mod);
  mont_mul(&a_m, a, &rr, mod, n0i);
  mont_mul(out, &a_m, b, mod, n0i);
  gsec_wipe(&rr, sizeof rr);
  gsec_wipe(&a_m, sizeof a_m);
  return 1;
}

int bn_modexp_ct(bn * out, const bn * base, const bn * exp, const bn * mod) {
  bn rr;
  bn one_m;
  bn base_m;
  bn acc;
  bn sq;
  bn prod;
  bn one;
  uint32_t n0i;
  int total;
  int bit;

  if ((mod->v[0] & 1u) == 0) {
    return 0;
  }
  n0i = mont_n0(mod->v[0]);
  mod_pow2(&rr, mod->n * 64, mod);
  mod_pow2(&one_m, mod->n * 32, mod);
  mont_mul(&base_m, base, &rr, mod, n0i);
  acc = one_m;
  total = mod->n * 32;
  for (bit = total - 1; bit >= 0; bit--) {
    int idx = bit / 32;
    uint32_t limb = idx < exp->n ? exp->v[idx] : 0;
    uint32_t on = (limb >> (bit % 32)) & 1u;

    mont_mul(&sq, &acc, &acc, mod, n0i);
    mont_mul(&prod, &sq, &base_m, mod, n0i);
    bn_cmov(&sq, &prod, on);
    acc = sq;
  }
  memset(&one, 0, sizeof one);
  one.n = mod->n;
  one.v[0] = 1;
  mont_mul(out, &acc, &one, mod, n0i);
  gsec_wipe(&rr, sizeof rr);
  gsec_wipe(&one_m, sizeof one_m);
  gsec_wipe(&base_m, sizeof base_m);
  gsec_wipe(&acc, sizeof acc);
  gsec_wipe(&sq, sizeof sq);
  gsec_wipe(&prod, sizeof prod);
  gsec_wipe(&one, sizeof one);
  return 1;
}

/*
 * Binary extended gcd. x2 * a ≡ v (mod n) is the invariant, and v is 1
 * when u first reaches 0, so x2 is the inverse. The step count is four
 * times the limb width. Once u is 0 it stays even, and only u and x1
 * move, so extra steps leave x2 alone.
 */
int bn_modinv_ct(bn * out, const bn * a, const bn * mod) {
  bn u;
  bn v;
  bn x1;
  bn x2;
  bn u0;
  bn v0;
  bn x10;
  bn x20;
  bn u_s;
  bn v_s;
  bn x1_s;
  bn x2_s;
  bn u_minus;
  bn v_minus;
  bn x1_minus;
  bn x2_minus;
  bn diff;
  int steps;
  int s;

  if ((mod->v[0] & 1u) == 0) {
    return 0;
  }
  memset(&u, 0, sizeof u);
  memset(&v, 0, sizeof v);
  memset(&x1, 0, sizeof x1);
  memset(&x2, 0, sizeof x2);
  memset(&diff, 0, sizeof diff);
  u = *a;
  for (s = a->n; s < BN_LIMBS; s++) {
    u.v[s] = 0;
  }
  u.n = mod->n;
  v = *mod;
  v.n = mod->n;
  x1.n = mod->n;
  x1.v[0] = 1;
  x2.n = mod->n;
  steps = mod->n * 128;
  for (s = 0; s < steps; s++) {
    uint32_t u_even;
    uint32_t v_even;
    uint32_t do_u;
    uint32_t do_v;
    uint32_t do_sub;
    uint32_t u_ge;
    uint32_t sub_u;
    uint32_t sub_v;
    uint32_t borrow;

    u0 = u;
    v0 = v;
    x10 = x1;
    x20 = x2;
    u_even = (u0.v[0] & 1u) ^ 1u;
    v_even = (v0.v[0] & 1u) ^ 1u;
    borrow = bn_sub(&diff, &u0, &v0);
    u_ge = borrow ^ 1u;
    do_u = u_even;
    do_v = v_even & (do_u ^ 1u);
    do_sub = (do_u | do_v) ^ 1u;
    sub_u = do_sub & u_ge;
    sub_v = do_sub & (u_ge ^ 1u);
    u_s = u0;
    bn_shr1(&u_s, 0);
    bn_halve_mod(&x1_s, &x10, mod);
    v_s = v0;
    bn_shr1(&v_s, 0);
    bn_halve_mod(&x2_s, &x20, mod);
    bn_sub(&u_minus, &u0, &v0);
    bn_sub_mod(&x1_minus, &x10, &x20, mod);
    bn_sub(&v_minus, &v0, &u0);
    bn_sub_mod(&x2_minus, &x20, &x10, mod);
    u = u0;
    bn_cmov(&u, &u_s, do_u);
    bn_cmov(&u, &u_minus, sub_u);
    v = v0;
    bn_cmov(&v, &v_s, do_v);
    bn_cmov(&v, &v_minus, sub_v);
    x1 = x10;
    bn_cmov(&x1, &x1_s, do_u);
    bn_cmov(&x1, &x1_minus, sub_u);
    x2 = x20;
    bn_cmov(&x2, &x2_s, do_v);
    bn_cmov(&x2, &x2_minus, sub_v);
  }
  *out = x2;
  out->n = mod->n;
  gsec_wipe(&u, sizeof u);
  gsec_wipe(&v, sizeof v);
  gsec_wipe(&x1, sizeof x1);
  gsec_wipe(&x2, sizeof x2);
  gsec_wipe(&u0, sizeof u0);
  gsec_wipe(&v0, sizeof v0);
  gsec_wipe(&x10, sizeof x10);
  gsec_wipe(&x20, sizeof x20);
  gsec_wipe(&u_s, sizeof u_s);
  gsec_wipe(&v_s, sizeof v_s);
  gsec_wipe(&x1_s, sizeof x1_s);
  gsec_wipe(&x2_s, sizeof x2_s);
  gsec_wipe(&u_minus, sizeof u_minus);
  gsec_wipe(&v_minus, sizeof v_minus);
  gsec_wipe(&x1_minus, sizeof x1_minus);
  gsec_wipe(&x2_minus, sizeof x2_minus);
  gsec_wipe(&diff, sizeof diff);
  return 1;
}
