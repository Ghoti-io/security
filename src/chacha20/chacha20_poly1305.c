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
 * AEAD_CHACHA20_POLY1305. ChaCha20 is add, rotate, and xor. Poly1305
 * multiplies in schoolbook 26-bit limbs. A key byte, a nonce byte, and
 * a message byte are not a branch condition and not a table index.
 * The block counter is public, because it follows the length.
 *
 * Counter 0 produces the Poly1305 key. Encryption starts at counter 1.
 * That is RFC 8439, and it is not the same counter as AES-CTR.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/chacha20_poly1305.h>
#include <ghoti.io/security/secret.h>

#include <stdint.h>

static uint32_t load32(const unsigned char p[4]) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
      ((uint32_t)p[3] << 24);
}

static void store32(unsigned char p[4], uint32_t v) {
  p[0] = (unsigned char)v;
  p[1] = (unsigned char)(v >> 8);
  p[2] = (unsigned char)(v >> 16);
  p[3] = (unsigned char)(v >> 24);
}

static uint32_t rotl32(uint32_t v, unsigned n) {
  return (v << n) | (v >> (32u - n));
}

static void quarter(uint32_t s[16], unsigned a, unsigned b, unsigned c,
    unsigned d) {
  s[a] += s[b];
  s[d] ^= s[a];
  s[d] = rotl32(s[d], 16);
  s[c] += s[d];
  s[b] ^= s[c];
  s[b] = rotl32(s[b], 12);
  s[a] += s[b];
  s[d] ^= s[a];
  s[d] = rotl32(s[d], 8);
  s[c] += s[d];
  s[b] ^= s[c];
  s[b] = rotl32(s[b], 7);
}

static void chacha20_block(unsigned char out[64], const unsigned char key[32],
    const unsigned char nonce[12], uint32_t counter) {
  uint32_t s[16];
  uint32_t w[16];
  unsigned i;

  s[0] = 0x61707865u;
  s[1] = 0x3320646eu;
  s[2] = 0x79622d32u;
  s[3] = 0x6b206574u;
  for (i = 0; i < 8u; i++) {
    s[4u + i] = load32(key + 4u * i);
  }
  s[12] = counter;
  s[13] = load32(nonce);
  s[14] = load32(nonce + 4);
  s[15] = load32(nonce + 8);
  for (i = 0; i < 16u; i++) {
    w[i] = s[i];
  }
  for (i = 0; i < 10u; i++) {
    quarter(w, 0, 4, 8, 12);
    quarter(w, 1, 5, 9, 13);
    quarter(w, 2, 6, 10, 14);
    quarter(w, 3, 7, 11, 15);
    quarter(w, 0, 5, 10, 15);
    quarter(w, 1, 6, 11, 12);
    quarter(w, 2, 7, 8, 13);
    quarter(w, 3, 4, 9, 14);
  }
  for (i = 0; i < 16u; i++) {
    store32(out + 4u * i, w[i] + s[i]);
  }
  gsec_wipe(s, sizeof s);
  gsec_wipe(w, sizeof w);
}

struct poly {
  uint32_t r[5];
  uint32_t h[5];
  unsigned char s[16];
  unsigned char buf[16];
  size_t n;
};

static void poly_init(struct poly * p, const unsigned char otk[32]) {
  unsigned i;
  uint32_t t0;
  uint32_t t1;
  uint32_t t2;
  uint32_t t3;

  for (i = 0; i < 5u; i++) {
    p->h[i] = 0;
  }
  p->n = 0;
  t0 = load32(otk);
  t1 = load32(otk + 3);
  t2 = load32(otk + 6);
  t3 = load32(otk + 9);
  p->r[0] = t0 & 0x3ffffffu;
  p->r[1] = (t1 >> 2) & 0x3ffff03u;
  p->r[2] = (t2 >> 4) & 0x3ffc0ffu;
  p->r[3] = (t3 >> 6) & 0x3f03fffu;
  p->r[4] = (load32(otk + 12) >> 8) & 0x00fffffu;
  for (i = 0; i < 16u; i++) {
    p->s[i] = otk[16u + i];
    p->buf[i] = 0;
  }
}

static void poly_block(struct poly * p, unsigned hibit) {
  uint32_t h0 = p->h[0];
  uint32_t h1 = p->h[1];
  uint32_t h2 = p->h[2];
  uint32_t h3 = p->h[3];
  uint32_t h4 = p->h[4];
  uint32_t r0 = p->r[0];
  uint32_t r1 = p->r[1];
  uint32_t r2 = p->r[2];
  uint32_t r3 = p->r[3];
  uint32_t r4 = p->r[4];
  uint32_t s1 = r1 * 5u;
  uint32_t s2 = r2 * 5u;
  uint32_t s3 = r3 * 5u;
  uint32_t s4 = r4 * 5u;
  uint32_t t0 = load32(p->buf);
  uint32_t t1 = load32(p->buf + 4);
  uint32_t t2 = load32(p->buf + 8);
  uint32_t t3 = load32(p->buf + 12);
  uint64_t d0;
  uint64_t d1;
  uint64_t d2;
  uint64_t d3;
  uint64_t d4;
  uint64_t c;

  h0 += t0 & 0x3ffffffu;
  h1 += ((t0 >> 26) | (t1 << 6)) & 0x3ffffffu;
  h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffffu;
  h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffffu;
  h4 += (t3 >> 8) | (hibit << 24);

  d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 +
      (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
  d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 +
      (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
  d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 +
      (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
  d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 +
      (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
  d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 +
      (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

  c = d0 >> 26;
  h0 = (uint32_t)d0 & 0x3ffffffu;
  d1 += c;
  c = d1 >> 26;
  h1 = (uint32_t)d1 & 0x3ffffffu;
  d2 += c;
  c = d2 >> 26;
  h2 = (uint32_t)d2 & 0x3ffffffu;
  d3 += c;
  c = d3 >> 26;
  h3 = (uint32_t)d3 & 0x3ffffffu;
  d4 += c;
  c = d4 >> 26;
  h4 = (uint32_t)d4 & 0x3ffffffu;
  h0 += (uint32_t)c * 5u;
  c = h0 >> 26;
  h0 &= 0x3ffffffu;
  h1 += (uint32_t)c;

  p->h[0] = h0;
  p->h[1] = h1;
  p->h[2] = h2;
  p->h[3] = h3;
  p->h[4] = h4;
}

static void poly_update(struct poly * p, const unsigned char * m, size_t n) {
  while (n > 0) {
    size_t room = 16u - p->n;
    size_t take = n < room ? n : room;
    size_t i;

    for (i = 0; i < take; i++) {
      p->buf[p->n + i] = m[i];
    }
    p->n += take;
    m += take;
    n -= take;
    if (p->n == 16u) {
      poly_block(p, 1u);
      p->n = 0;
    }
  }
}

static void poly_pad(struct poly * p) {
  unsigned char z[16];
  size_t need;
  unsigned i;

  if (p->n == 0) {
    return;
  }
  need = 16u - p->n;
  for (i = 0; i < 16u; i++) {
    z[i] = 0;
  }
  poly_update(p, z, need);
  gsec_wipe(z, sizeof z);
}

static void poly_finish(struct poly * p, unsigned char tag[16]) {
  uint32_t h0 = p->h[0];
  uint32_t h1 = p->h[1];
  uint32_t h2 = p->h[2];
  uint32_t h3 = p->h[3];
  uint32_t h4 = p->h[4];
  uint32_t g0;
  uint32_t g1;
  uint32_t g2;
  uint32_t g3;
  uint32_t g4;
  uint32_t mask;
  uint32_t c;
  uint64_t f;

  c = h1 >> 26;
  h1 &= 0x3ffffffu;
  h2 += c;
  c = h2 >> 26;
  h2 &= 0x3ffffffu;
  h3 += c;
  c = h3 >> 26;
  h3 &= 0x3ffffffu;
  h4 += c;
  c = h4 >> 26;
  h4 &= 0x3ffffffu;
  h0 += c * 5u;
  c = h0 >> 26;
  h0 &= 0x3ffffffu;
  h1 += c;

  g0 = h0 + 5u;
  c = g0 >> 26;
  g0 &= 0x3ffffffu;
  g1 = h1 + c;
  c = g1 >> 26;
  g1 &= 0x3ffffffu;
  g2 = h2 + c;
  c = g2 >> 26;
  g2 &= 0x3ffffffu;
  g3 = h3 + c;
  c = g3 >> 26;
  g3 &= 0x3ffffffu;
  g4 = h4 + c - (1u << 26);

  mask = (g4 >> 31) - 1u;
  g0 &= mask;
  g1 &= mask;
  g2 &= mask;
  g3 &= mask;
  g4 &= mask;
  mask = ~mask;
  h0 = (h0 & mask) | g0;
  h1 = (h1 & mask) | g1;
  h2 = (h2 & mask) | g2;
  h3 = (h3 & mask) | g3;
  h4 = (h4 & mask) | g4;

  h0 = (h0 | (h1 << 26)) & 0xffffffffu;
  h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffffu;
  h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffffu;
  h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffffu;

  f = (uint64_t)h0 + load32(p->s);
  h0 = (uint32_t)f;
  f = (uint64_t)h1 + load32(p->s + 4) + (f >> 32);
  h1 = (uint32_t)f;
  f = (uint64_t)h2 + load32(p->s + 8) + (f >> 32);
  h2 = (uint32_t)f;
  f = (uint64_t)h3 + load32(p->s + 12) + (f >> 32);
  h3 = (uint32_t)f;

  store32(tag, h0);
  store32(tag + 4, h1);
  store32(tag + 8, h2);
  store32(tag + 12, h3);
}

static int pt_len_ok(size_t n) {
  return (uint64_t)n <= (((UINT64_C(1) << 32) - 1u) * 64u);
}

static int partial_overlap(const unsigned char * a, const unsigned char * b,
    size_t n) {
  if (n == 0 || a == b) {
    return 0;
  }
  if (a < b) {
    return (size_t)(b - a) < n;
  }
  return (size_t)(a - b) < n;
}

static int ranges_overlap(const unsigned char * a, size_t an,
    const unsigned char * b, size_t bn) {
  if (an == 0 || bn == 0) {
    return 0;
  }
  if (a <= b) {
    return (size_t)(b - a) < an;
  }
  return (size_t)(a - b) < bn;
}

static void store_le64(unsigned char out[8], uint64_t n) {
  unsigned i;

  for (i = 0; i < 8u; i++) {
    out[i] = (unsigned char)n;
    n >>= 8;
  }
}

static GSEC_Result crypt(const unsigned char * key, const unsigned char * nonce,
    const unsigned char * aad, size_t aad_len, const unsigned char * in,
    unsigned char * out, size_t n, unsigned char tag[16], int decrypt) {
  struct poly mac;
  unsigned char otk_block[64];
  unsigned char stream[64];
  unsigned char lengths[16];
  uint32_t counter = 1u;
  size_t off;
  GSEC_Result result = GSEC_OK;

  chacha20_block(otk_block, key, nonce, 0);
  poly_init(&mac, otk_block);
  gsec_wipe(otk_block, sizeof otk_block);
  if (aad_len != 0) {
    poly_update(&mac, aad, aad_len);
  }
  poly_pad(&mac);
  for (off = 0; off < n; ) {
    size_t take = n - off;
    size_t i;

    if (take > 64u) {
      take = 64u;
    }
    if (counter == 0u) {
      if (off != 0) {
        gsec_wipe(out, off);
      }
      result = GSEC_ERR_LIMIT;
      break;
    }
    chacha20_block(stream, key, nonce, counter);
    counter++;
    /* Authenticate the ciphertext before an in-place decrypt overwrites it. */
    if (decrypt) {
      poly_update(&mac, in + off, take);
    }
    for (i = 0; i < take; i++) {
      out[off + i] = (unsigned char)(in[off + i] ^ stream[i]);
    }
    if (!decrypt) {
      poly_update(&mac, out + off, take);
    }
    gsec_wipe(stream, sizeof stream);
    off += take;
  }
  if (result == GSEC_OK) {
    poly_pad(&mac);
    store_le64(lengths, (uint64_t)aad_len);
    store_le64(lengths + 8, (uint64_t)n);
    poly_update(&mac, lengths, sizeof lengths);
    poly_finish(&mac, tag);
  }
  gsec_wipe(&mac, sizeof mac);
  gsec_wipe(lengths, sizeof lengths);
  gsec_wipe(stream, sizeof stream);
  return result;
}

GSEC_Result gsec_chacha20_poly1305_encrypt(const void * key, const void * nonce,
    const void * aad, size_t aad_len, const void * pt, size_t pt_len, void * ct,
    void * tag) {
  const unsigned char * src;
  unsigned char * dst;
  unsigned char * tag_out;
  unsigned char full[16];
  unsigned i;
  GSEC_Result result;

  if (key == NULL || nonce == NULL || (aad == NULL && aad_len != 0) ||
      tag == NULL) {
    return GSEC_ERR_INVALID;
  }
  if (!pt_len_ok(pt_len)) {
    return GSEC_ERR_LIMIT;
  }
  if ((pt == NULL || ct == NULL) && pt_len != 0) {
    return GSEC_ERR_INVALID;
  }
  src = (const unsigned char *)pt;
  dst = (unsigned char *)ct;
  tag_out = (unsigned char *)tag;
  if (partial_overlap(src, dst, pt_len) ||
      ranges_overlap(tag_out, GSEC_POLY1305_TAG_LEN, src, pt_len) ||
      ranges_overlap(tag_out, GSEC_POLY1305_TAG_LEN, dst, pt_len)) {
    return GSEC_ERR_INVALID;
  }
  result = crypt((const unsigned char *)key, (const unsigned char *)nonce,
      (const unsigned char *)aad, aad_len, src, dst, pt_len, full, 0);
  if (result == GSEC_OK) {
    for (i = 0; i < GSEC_POLY1305_TAG_LEN; i++) {
      tag_out[i] = full[i];
    }
  }
  gsec_wipe(full, sizeof full);
  return result;
}

GSEC_Result gsec_chacha20_poly1305_decrypt(const void * key, const void * nonce,
    const void * aad, size_t aad_len, const void * ct, size_t ct_len, void * pt,
    const void * tag) {
  const unsigned char * src;
  unsigned char * dst;
  unsigned char given[16];
  unsigned char full[16];
  unsigned i;
  GSEC_Result result;

  if (key == NULL || nonce == NULL || (aad == NULL && aad_len != 0) ||
      tag == NULL) {
    return GSEC_ERR_INVALID;
  }
  if (!pt_len_ok(ct_len)) {
    return GSEC_ERR_LIMIT;
  }
  if ((ct == NULL || pt == NULL) && ct_len != 0) {
    return GSEC_ERR_INVALID;
  }
  src = (const unsigned char *)ct;
  dst = (unsigned char *)pt;
  if (partial_overlap(src, dst, ct_len)) {
    return GSEC_ERR_INVALID;
  }
  for (i = 0; i < 16u; i++) {
    given[i] = ((const unsigned char *)tag)[i];
  }
  result = crypt((const unsigned char *)key, (const unsigned char *)nonce,
      (const unsigned char *)aad, aad_len, src, dst, ct_len, full, 1);
  if (result == GSEC_OK) {
    result = gsec_equal(given, full, GSEC_POLY1305_TAG_LEN);
    if (result != GSEC_OK && ct_len != 0) {
      gsec_wipe(dst, ct_len);
    }
  }
  gsec_wipe(given, sizeof given);
  gsec_wipe(full, sizeof full);
  return result;
}
