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
 * Montgomery multiplication modulo an odd public modulus. One conditional
 * subtraction finishes each product. The exponentiation walks the public
 * exponent from the high bit.
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

static void bn_sub(bn * r, const bn * a, const bn * b) {
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
  r->n = a->n;
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
  if (t[len] != 0 || bn_cmp(r, mod) >= 0) {
    bn_sub(r, r, mod);
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
