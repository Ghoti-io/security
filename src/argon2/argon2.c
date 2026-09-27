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
 * Argon2 version 0x13. BLAKE2b is the internal hash. The compression
 * is the BlaMka round. Lanes are filled on this thread. Argon2d and
 * Argon2id index memory with a password-derived word.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/allocator.h>
#include <ghoti.io/security/argon2.h>
#include <ghoti.io/security/secret.h>

#include <stdint.h>
#include <string.h>

#define BLOCK_QWORDS 128u
#define BLOCK_BYTES 1024u
#define SYNC_POINTS 4u
#define ADDRESSES 128u
#define PREHASH 64u
#define SEED_BYTES 72u
#define VERSION 0x13u

typedef struct Block {
  uint64_t v[BLOCK_QWORDS];
} Block;

static uint64_t rotr64(uint64_t x, unsigned n) {
  return (x >> n) | (x << (64u - n));
}

static uint64_t load64(const unsigned char *p) {
  uint64_t w = 0;
  unsigned i;

  for (i = 0; i < 8; i++) {
    w |= (uint64_t)p[i] << (8u * i);
  }
  return w;
}

static void store32(unsigned char p[4], uint32_t w) {
  p[0] = (unsigned char)w;
  p[1] = (unsigned char)(w >> 8);
  p[2] = (unsigned char)(w >> 16);
  p[3] = (unsigned char)(w >> 24);
}

static void store64(unsigned char p[8], uint64_t w) {
  unsigned i;

  for (i = 0; i < 8; i++) {
    p[i] = (unsigned char)(w >> (8u * i));
  }
}

static const uint64_t blake2b_iv[8] = {
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
  0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const unsigned char blake2b_sigma[12][16] = {
  {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
  {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
  {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
  {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
  {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
  {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
  {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
  {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
  {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
  {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
  {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
  {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
};

typedef struct Blake2b {
  uint64_t h[8];
  uint64_t t;
  unsigned char buf[128];
  size_t fill;
} Blake2b;

static void blake2b_g(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d,
    uint64_t x, uint64_t y) {
  *a = *a + *b + x;
  *d = rotr64(*d ^ *a, 32);
  *c = *c + *d;
  *b = rotr64(*b ^ *c, 24);
  *a = *a + *b + y;
  *d = rotr64(*d ^ *a, 16);
  *c = *c + *d;
  *b = rotr64(*b ^ *c, 63);
}

static void blake2b_compress(Blake2b *s, int last) {
  uint64_t m[16];
  uint64_t v[16];
  unsigned i;
  unsigned r;

  for (i = 0; i < 16; i++) {
    m[i] = load64(s->buf + i * 8u);
  }
  for (i = 0; i < 8; i++) {
    v[i] = s->h[i];
    v[i + 8] = blake2b_iv[i];
  }
  v[12] ^= s->t;
  if (last) {
    v[14] = ~v[14];
  }
  for (r = 0; r < 12; r++) {
    const unsigned char *sig = blake2b_sigma[r];

    blake2b_g(&v[0], &v[4], &v[8], &v[12], m[sig[0]], m[sig[1]]);
    blake2b_g(&v[1], &v[5], &v[9], &v[13], m[sig[2]], m[sig[3]]);
    blake2b_g(&v[2], &v[6], &v[10], &v[14], m[sig[4]], m[sig[5]]);
    blake2b_g(&v[3], &v[7], &v[11], &v[15], m[sig[6]], m[sig[7]]);
    blake2b_g(&v[0], &v[5], &v[10], &v[15], m[sig[8]], m[sig[9]]);
    blake2b_g(&v[1], &v[6], &v[11], &v[12], m[sig[10]], m[sig[11]]);
    blake2b_g(&v[2], &v[7], &v[8], &v[13], m[sig[12]], m[sig[13]]);
    blake2b_g(&v[3], &v[4], &v[9], &v[14], m[sig[14]], m[sig[15]]);
  }
  for (i = 0; i < 8; i++) {
    s->h[i] ^= v[i] ^ v[i + 8];
  }
}

static void blake2b_init(Blake2b *s, size_t outlen) {
  unsigned i;

  for (i = 0; i < 8; i++) {
    s->h[i] = blake2b_iv[i];
  }
  s->h[0] ^= 0x01010000ULL ^ (uint64_t)outlen;
  s->t = 0;
  s->fill = 0;
  memset(s->buf, 0, sizeof s->buf);
}

static void blake2b_update(Blake2b *s, const unsigned char *in, size_t len) {
  while (len != 0) {
    size_t room = sizeof s->buf - s->fill;
    size_t take = len < room ? len : room;

    memcpy(s->buf + s->fill, in, take);
    s->fill += take;
    in += take;
    len -= take;
    if (s->fill == sizeof s->buf) {
      s->t += sizeof s->buf;
      blake2b_compress(s, 0);
      s->fill = 0;
    }
  }
}

static void blake2b_final(Blake2b *s, unsigned char *out, size_t outlen) {
  unsigned i;

  s->t += s->fill;
  memset(s->buf + s->fill, 0, sizeof s->buf - s->fill);
  blake2b_compress(s, 1);
  for (i = 0; i < outlen; i++) {
    out[i] = (unsigned char)(s->h[i / 8u] >> (8u * (i % 8u)));
  }
}

static void blake2b_wipe(Blake2b *s) {
  gsec_wipe(s, sizeof *s);
}

static void blake2b_oneshot(unsigned char *out, size_t outlen,
    const unsigned char *in, size_t inlen) {
  Blake2b s;

  blake2b_init(&s, outlen);
  blake2b_update(&s, in, inlen);
  blake2b_final(&s, out, outlen);
  blake2b_wipe(&s);
}

static void blake2b_long(unsigned char *out, size_t outlen,
    const unsigned char *in, size_t inlen) {
  unsigned char lenb[4];
  unsigned char buf[64];
  unsigned char next[64];
  Blake2b s;
  size_t left;

  store32(lenb, (uint32_t)outlen);
  if (outlen <= 64u) {
    blake2b_init(&s, outlen);
    blake2b_update(&s, lenb, sizeof lenb);
    blake2b_update(&s, in, inlen);
    blake2b_final(&s, out, outlen);
    blake2b_wipe(&s);
    return;
  }
  blake2b_init(&s, 64);
  blake2b_update(&s, lenb, sizeof lenb);
  blake2b_update(&s, in, inlen);
  blake2b_final(&s, buf, 64);
  blake2b_wipe(&s);
  memcpy(out, buf, 32);
  out += 32;
  left = outlen - 32u;
  while (left > 64u) {
    blake2b_oneshot(next, 64, buf, 64);
    memcpy(buf, next, 64);
    memcpy(out, buf, 32);
    out += 32;
    left -= 32u;
  }
  blake2b_oneshot(next, left, buf, 64);
  memcpy(out, next, left);
  gsec_wipe(buf, sizeof buf);
  gsec_wipe(next, sizeof next);
}

static uint64_t blamka(uint64_t x, uint64_t y) {
  uint64_t xy = (x & 0xffffffffULL) * (y & 0xffffffffULL);

  return x + y + 2u * xy;
}

static void blamka_g(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d) {
  *a = blamka(*a, *b);
  *d = rotr64(*d ^ *a, 32);
  *c = blamka(*c, *d);
  *b = rotr64(*b ^ *c, 24);
  *a = blamka(*a, *b);
  *d = rotr64(*d ^ *a, 16);
  *c = blamka(*c, *d);
  *b = rotr64(*b ^ *c, 63);
}

static void blake2_round_nomsg(uint64_t *v0, uint64_t *v1, uint64_t *v2,
    uint64_t *v3, uint64_t *v4, uint64_t *v5, uint64_t *v6, uint64_t *v7,
    uint64_t *v8, uint64_t *v9, uint64_t *v10, uint64_t *v11, uint64_t *v12,
    uint64_t *v13, uint64_t *v14, uint64_t *v15) {
  blamka_g(v0, v4, v8, v12);
  blamka_g(v1, v5, v9, v13);
  blamka_g(v2, v6, v10, v14);
  blamka_g(v3, v7, v11, v15);
  blamka_g(v0, v5, v10, v15);
  blamka_g(v1, v6, v11, v12);
  blamka_g(v2, v7, v8, v13);
  blamka_g(v3, v4, v9, v14);
}

static void fill_block(const Block *prev, const Block *ref, Block *next,
    int with_xor) {
  Block r;
  Block tmp;
  unsigned i;

  memcpy(&r, ref, sizeof r);
  for (i = 0; i < BLOCK_QWORDS; i++) {
    r.v[i] ^= prev->v[i];
  }
  memcpy(&tmp, &r, sizeof tmp);
  if (with_xor) {
    for (i = 0; i < BLOCK_QWORDS; i++) {
      tmp.v[i] ^= next->v[i];
    }
  }
  for (i = 0; i < 8; i++) {
    blake2_round_nomsg(&r.v[16u * i], &r.v[16u * i + 1], &r.v[16u * i + 2],
        &r.v[16u * i + 3], &r.v[16u * i + 4], &r.v[16u * i + 5],
        &r.v[16u * i + 6], &r.v[16u * i + 7], &r.v[16u * i + 8],
        &r.v[16u * i + 9], &r.v[16u * i + 10], &r.v[16u * i + 11],
        &r.v[16u * i + 12], &r.v[16u * i + 13], &r.v[16u * i + 14],
        &r.v[16u * i + 15]);
  }
  for (i = 0; i < 8; i++) {
    blake2_round_nomsg(&r.v[2u * i], &r.v[2u * i + 1], &r.v[2u * i + 16],
        &r.v[2u * i + 17], &r.v[2u * i + 32], &r.v[2u * i + 33],
        &r.v[2u * i + 48], &r.v[2u * i + 49], &r.v[2u * i + 64],
        &r.v[2u * i + 65], &r.v[2u * i + 80], &r.v[2u * i + 81],
        &r.v[2u * i + 96], &r.v[2u * i + 97], &r.v[2u * i + 112],
        &r.v[2u * i + 113]);
  }
  for (i = 0; i < BLOCK_QWORDS; i++) {
    next->v[i] = tmp.v[i] ^ r.v[i];
  }
  gsec_wipe(&r, sizeof r);
  gsec_wipe(&tmp, sizeof tmp);
}

static void load_block(Block *dst, const unsigned char *in) {
  unsigned i;

  for (i = 0; i < BLOCK_QWORDS; i++) {
    dst->v[i] = load64(in + i * 8u);
  }
}

static void store_block(unsigned char *out, const Block *src) {
  unsigned i;

  for (i = 0; i < BLOCK_QWORDS; i++) {
    store64(out + i * 8u, src->v[i]);
  }
}

static uint32_t index_alpha(uint32_t pass, uint32_t slice, uint32_t index,
    uint32_t lane_length, uint32_t segment_length, uint32_t pseudo,
    int same_lane) {
  uint32_t area;
  uint32_t area_minus;
  uint64_t relative;
  uint32_t start;

  if (pass == 0) {
    if (slice == 0) {
      area = index - 1u;
    } else if (same_lane) {
      area = slice * segment_length + index - 1u;
    } else {
      area = slice * segment_length + (index == 0 ? 0xffffffffu : 0u);
    }
  } else if (same_lane) {
    area = lane_length - segment_length + index - 1u;
  } else {
    area = lane_length - segment_length + (index == 0 ? 0xffffffffu : 0u);
  }
  relative = pseudo;
  relative = (relative * relative) >> 32;
  area_minus = area - 1u;
  relative = (uint64_t)area_minus - (((uint64_t)area * relative) >> 32);
  start = 0;
  if (pass != 0) {
    start = slice == SYNC_POINTS - 1u ? 0u : (slice + 1u) * segment_length;
  }
  return (start + (uint32_t)relative) % lane_length;
}

static void next_addresses(Block *address, Block *input, const Block *zero) {
  input->v[6]++;
  fill_block(zero, input, address, 0);
  fill_block(zero, address, address, 0);
}

static void fill_segment(Block *memory, uint32_t lane_length,
    uint32_t segment_length, uint32_t blocks, uint32_t passes, uint32_t lanes,
    uint32_t type, uint32_t pass, uint32_t lane, uint32_t slice) {
  Block address;
  Block input;
  Block zero;
  int indep;
  uint32_t starting = 0;
  uint32_t curr;
  uint32_t prev;
  uint32_t i;

  indep = type == GSEC_ARGON2_I ||
      (type == GSEC_ARGON2_ID && pass == 0 && slice < SYNC_POINTS / 2u);
  memset(&zero, 0, sizeof zero);
  memset(&input, 0, sizeof input);
  memset(&address, 0, sizeof address);
  if (indep) {
    input.v[0] = pass;
    input.v[1] = lane;
    input.v[2] = slice;
    input.v[3] = blocks;
    input.v[4] = passes;
    input.v[5] = type;
  }
  if (pass == 0 && slice == 0) {
    starting = 2;
    if (indep) {
      next_addresses(&address, &input, &zero);
    }
  }
  curr = lane * lane_length + slice * segment_length + starting;
  if (curr % lane_length == 0) {
    prev = curr + lane_length - 1u;
  } else {
    prev = curr - 1u;
  }
  for (i = starting; i < segment_length; i++, curr++, prev++) {
    uint64_t pseudo;
    uint32_t ref_lane;
    uint32_t ref_index;
    int with_xor;

    if (curr % lane_length == 1u) {
      prev = curr - 1u;
    }
    if (indep) {
      if (i % ADDRESSES == 0) {
        next_addresses(&address, &input, &zero);
      }
      pseudo = address.v[i % ADDRESSES];
    } else {
      pseudo = memory[prev].v[0];
    }
    ref_lane = (uint32_t)((pseudo >> 32) % lanes);
    if (pass == 0 && slice == 0) {
      ref_lane = lane;
    }
    ref_index = index_alpha(pass, slice, i, lane_length, segment_length,
        (uint32_t)pseudo, ref_lane == lane);
    with_xor = pass != 0;
    fill_block(&memory[prev], &memory[ref_lane * lane_length + ref_index],
        &memory[curr], with_xor);
  }
  gsec_wipe(&address, sizeof address);
  gsec_wipe(&input, sizeof input);
  gsec_wipe(&zero, sizeof zero);
}

static int fits_u32(size_t n) {
  return n <= UINT32_MAX;
}

GSEC_Result gsec_argon2(uint32_t type, const void * password,
    size_t password_len, const void * salt, size_t salt_len,
    const void * secret, size_t secret_len, const void * ad, size_t ad_len,
    uint32_t memory_kib, uint32_t passes, uint32_t lanes, void * tag,
    size_t tag_len) {
  const GSEC_Allocator * alloc;
  Block * memory = NULL;
  unsigned char seed[SEED_BYTES];
  unsigned char block_bytes[BLOCK_BYTES];
  Blake2b hash;
  unsigned char value[4];
  uint32_t blocks;
  uint32_t segment;
  uint32_t lane_length;
  uint32_t pass;
  uint32_t slice;
  uint32_t lane;
  GSEC_Result result = GSEC_OK;

  if (type > GSEC_ARGON2_ID || passes == 0 || lanes == 0 ||
      lanes > GSEC_ARGON2_MEMORY_MAX / 8u || tag == NULL ||
      tag_len < GSEC_ARGON2_TAG_MIN || tag_len > GSEC_ARGON2_TAG_MAX ||
      salt == NULL || salt_len < GSEC_ARGON2_SALT_MIN ||
      (password == NULL && password_len != 0) ||
      (secret == NULL && secret_len != 0) ||
      (ad == NULL && ad_len != 0) || !fits_u32(password_len) ||
      !fits_u32(salt_len) || !fits_u32(secret_len) || !fits_u32(ad_len)) {
    return GSEC_ERR_INVALID;
  }
  if (memory_kib < 8u * lanes) {
    return GSEC_ERR_INVALID;
  }
  if (memory_kib > GSEC_ARGON2_MEMORY_MAX) {
    return GSEC_ERR_LIMIT;
  }
  blocks = lanes * SYNC_POINTS * (memory_kib / (lanes * SYNC_POINTS));
  segment = blocks / (lanes * SYNC_POINTS);
  lane_length = segment * SYNC_POINTS;
  blocks = lane_length * lanes;
  alloc = gsec_allocator_default();
  memory = (Block *)alloc->calloc_fn(alloc->ctx, blocks, sizeof(Block));
  if (memory == NULL) {
    return GSEC_ERR_LIMIT;
  }
  blake2b_init(&hash, PREHASH);
  store32(value, lanes);
  blake2b_update(&hash, value, 4);
  store32(value, (uint32_t)tag_len);
  blake2b_update(&hash, value, 4);
  store32(value, memory_kib);
  blake2b_update(&hash, value, 4);
  store32(value, passes);
  blake2b_update(&hash, value, 4);
  store32(value, VERSION);
  blake2b_update(&hash, value, 4);
  store32(value, type);
  blake2b_update(&hash, value, 4);
  store32(value, (uint32_t)password_len);
  blake2b_update(&hash, value, 4);
  if (password_len != 0) {
    blake2b_update(&hash, (const unsigned char *)password, password_len);
  }
  store32(value, (uint32_t)salt_len);
  blake2b_update(&hash, value, 4);
  blake2b_update(&hash, (const unsigned char *)salt, salt_len);
  store32(value, (uint32_t)secret_len);
  blake2b_update(&hash, value, 4);
  if (secret_len != 0) {
    blake2b_update(&hash, (const unsigned char *)secret, secret_len);
  }
  store32(value, (uint32_t)ad_len);
  blake2b_update(&hash, value, 4);
  if (ad_len != 0) {
    blake2b_update(&hash, (const unsigned char *)ad, ad_len);
  }
  memset(seed, 0, sizeof seed);
  blake2b_final(&hash, seed, PREHASH);
  blake2b_wipe(&hash);
  for (lane = 0; lane < lanes; lane++) {
    store32(seed + PREHASH, 0);
    store32(seed + PREHASH + 4, lane);
    blake2b_long(block_bytes, BLOCK_BYTES, seed, SEED_BYTES);
    load_block(&memory[lane * lane_length], block_bytes);
    store32(seed + PREHASH, 1);
    blake2b_long(block_bytes, BLOCK_BYTES, seed, SEED_BYTES);
    load_block(&memory[lane * lane_length + 1], block_bytes);
  }
  for (pass = 0; pass < passes; pass++) {
    for (slice = 0; slice < SYNC_POINTS; slice++) {
      for (lane = 0; lane < lanes; lane++) {
        fill_segment(memory, lane_length, segment, blocks, passes, lanes,
            type, pass, lane, slice);
      }
    }
  }
  {
    Block last;
    unsigned i;

    memcpy(&last, &memory[lane_length - 1u], sizeof last);
    for (lane = 1; lane < lanes; lane++) {
      const Block * other = &memory[lane * lane_length + lane_length - 1u];

      for (i = 0; i < BLOCK_QWORDS; i++) {
        last.v[i] ^= other->v[i];
      }
    }
    store_block(block_bytes, &last);
    blake2b_long((unsigned char *)tag, tag_len, block_bytes, BLOCK_BYTES);
    gsec_wipe(&last, sizeof last);
  }
  gsec_wipe(memory, (size_t)blocks * sizeof(Block));
  gsec_wipe(seed, sizeof seed);
  gsec_wipe(block_bytes, sizeof block_bytes);
  gsec_wipe(value, sizeof value);
  alloc->free_fn(alloc->ctx, memory);
  return result;
}
