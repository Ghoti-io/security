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
 * HMAC is H((K' xor opad) || H((K' xor ipad) || message)). Which hash, and
 * therefore which block length, is the caller's choice and is public. The
 * bytes of the key are not a branch condition and not a table index.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/hmac.h>
#include <ghoti.io/security/secret.h>

#define GSEC_HMAC_MAGIC 0x484d4143u

typedef GSEC_Result (*init_fn)(void * ctx);
typedef GSEC_Result (*update_fn)(void * ctx, const void * data, size_t n);
typedef GSEC_Result (*final_fn)(void * ctx, unsigned char * out);
typedef GSEC_Result (*oneshot_fn)(const void * data, size_t n,
    unsigned char * out);

struct alg {
  uint32_t id;
  size_t digest_len;
  size_t block_len;
  init_fn init;
  update_fn update;
  final_fn final;
  oneshot_fn oneshot;
};

static GSEC_Result sha1_init(void * ctx) {
  return gsec_sha1_init((GSEC_Sha1 *)ctx);
}

static GSEC_Result sha1_update(void * ctx, const void * data, size_t n) {
  return gsec_sha1_update((GSEC_Sha1 *)ctx, data, n);
}

static GSEC_Result sha1_final(void * ctx, unsigned char * out) {
  return gsec_sha1_final((GSEC_Sha1 *)ctx, out);
}

static GSEC_Result sha256_init(void * ctx) {
  return gsec_sha256_init((GSEC_Sha256 *)ctx);
}

static GSEC_Result sha256_update(void * ctx, const void * data, size_t n) {
  return gsec_sha256_update((GSEC_Sha256 *)ctx, data, n);
}

static GSEC_Result sha256_final(void * ctx, unsigned char * out) {
  return gsec_sha256_final((GSEC_Sha256 *)ctx, out);
}

static GSEC_Result sha384_init(void * ctx) {
  return gsec_sha384_init((GSEC_Sha384 *)ctx);
}

static GSEC_Result sha384_update(void * ctx, const void * data, size_t n) {
  return gsec_sha384_update((GSEC_Sha384 *)ctx, data, n);
}

static GSEC_Result sha384_final(void * ctx, unsigned char * out) {
  return gsec_sha384_final((GSEC_Sha384 *)ctx, out);
}

static GSEC_Result sha512_init(void * ctx) {
  return gsec_sha512_init((GSEC_Sha512 *)ctx);
}

static GSEC_Result sha512_update(void * ctx, const void * data, size_t n) {
  return gsec_sha512_update((GSEC_Sha512 *)ctx, data, n);
}

static GSEC_Result sha512_final(void * ctx, unsigned char * out) {
  return gsec_sha512_final((GSEC_Sha512 *)ctx, out);
}

static const struct alg * find_alg(uint32_t hash) {
  static const struct alg algs[] = {
    { GSEC_HMAC_SHA1, GSEC_SHA1_DIGEST_LEN, GSEC_SHA1_BLOCK_LEN,
      sha1_init, sha1_update, sha1_final, gsec_sha1 },
    { GSEC_HMAC_SHA256, GSEC_SHA256_DIGEST_LEN, GSEC_SHA256_BLOCK_LEN,
      sha256_init, sha256_update, sha256_final, gsec_sha256 },
    { GSEC_HMAC_SHA384, GSEC_SHA384_DIGEST_LEN, GSEC_SHA384_BLOCK_LEN,
      sha384_init, sha384_update, sha384_final, gsec_sha384 },
    { GSEC_HMAC_SHA512, GSEC_SHA512_DIGEST_LEN, GSEC_SHA512_BLOCK_LEN,
      sha512_init, sha512_update, sha512_final, gsec_sha512 }
  };
  size_t i;

  for (i = 0; i < sizeof algs / sizeof algs[0]; i++) {
    if (algs[i].id == hash) {
      return &algs[i];
    }
  }
  return NULL;
}

static void * inner_of(GSEC_Hmac * ctx) {
  if (ctx->hash == GSEC_HMAC_SHA1) {
    return &ctx->inner.sha1;
  }
  if (ctx->hash == GSEC_HMAC_SHA256) {
    return &ctx->inner.sha256;
  }
  if (ctx->hash == GSEC_HMAC_SHA384) {
    return &ctx->inner.sha384;
  }
  return &ctx->inner.sha512;
}

static int live(const GSEC_Hmac * ctx) {
  return ctx->magic == GSEC_HMAC_MAGIC;
}

GSEC_Result gsec_hmac_init(GSEC_Hmac * ctx, uint32_t hash, const void * key,
    size_t key_len) {
  const struct alg * alg;
  unsigned char kpad[GSEC_SHA512_BLOCK_LEN];
  unsigned char hashed[GSEC_SHA512_DIGEST_LEN];
  const unsigned char * material;
  size_t material_len;
  size_t i;
  GSEC_Result result;

  if (ctx == NULL) {
    return GSEC_ERR_INVALID;
  }
  gsec_wipe(ctx, sizeof *ctx);
  alg = find_alg(hash);
  if (alg == NULL || (key == NULL && key_len > 0)) {
    return GSEC_ERR_INVALID;
  }

  gsec_wipe(kpad, sizeof kpad);
  gsec_wipe(hashed, sizeof hashed);
  if (key_len > alg->block_len) {
    result = alg->oneshot(key, key_len, hashed);
    if (result != GSEC_OK) {
      gsec_wipe(kpad, sizeof kpad);
      gsec_wipe(hashed, sizeof hashed);
      return result;
    }
    material = hashed;
    material_len = alg->digest_len;
  } else {
    material = (const unsigned char *)key;
    material_len = key_len;
  }

  for (i = 0; i < alg->block_len; i++) {
    unsigned char byte = 0;

    if (i < material_len) {
      byte = material[i];
    }
    kpad[i] = (unsigned char)(byte ^ 0x36u);
    ctx->opad[i] = (unsigned char)(byte ^ 0x5cu);
  }
  gsec_wipe(hashed, sizeof hashed);

  ctx->hash = hash;
  ctx->block_len = alg->block_len;
  ctx->digest_len = alg->digest_len;
  ctx->magic = GSEC_HMAC_MAGIC;
  result = alg->init(inner_of(ctx));
  if (result != GSEC_OK) {
    gsec_wipe(kpad, sizeof kpad);
    gsec_wipe(ctx, sizeof *ctx);
    return result;
  }
  result = alg->update(inner_of(ctx), kpad, alg->block_len);
  gsec_wipe(kpad, sizeof kpad);
  if (result != GSEC_OK) {
    gsec_wipe(ctx, sizeof *ctx);
    return result;
  }
  return GSEC_OK;
}

GSEC_Result gsec_hmac_update(GSEC_Hmac * ctx, const void * data, size_t n) {
  const struct alg * alg;

  if (ctx == NULL || !live(ctx)) {
    return GSEC_ERR_INVALID;
  }
  alg = find_alg(ctx->hash);
  if (alg == NULL) {
    return GSEC_ERR_INVALID;
  }
  return alg->update(inner_of(ctx), data, n);
}

GSEC_Result gsec_hmac_final(GSEC_Hmac * ctx, unsigned char * out) {
  const struct alg * alg;
  unsigned char inner[GSEC_SHA512_DIGEST_LEN];
  unsigned char opad[GSEC_SHA512_BLOCK_LEN];
  size_t digest_len;
  size_t block_len;
  GSEC_Hmac outer;
  GSEC_Result result;

  if (ctx == NULL || !live(ctx)) {
    return GSEC_ERR_INVALID;
  }
  if (out == NULL) {
    return GSEC_ERR_INVALID;
  }
  alg = find_alg(ctx->hash);
  if (alg == NULL) {
    gsec_wipe(ctx, sizeof *ctx);
    return GSEC_ERR_INVALID;
  }
  digest_len = ctx->digest_len;
  block_len = ctx->block_len;

  /* Copy the outer pad off the context before the inner hash's final
   * wipes its own state. The pad is still key material until the wipe
   * below. */
  gsec_wipe(opad, sizeof opad);
  {
    size_t i;
    for (i = 0; i < block_len; i++) {
      opad[i] = ctx->opad[i];
    }
  }
  result = alg->final(inner_of(ctx), inner);
  if (result != GSEC_OK) {
    gsec_wipe(inner, sizeof inner);
    gsec_wipe(opad, sizeof opad);
    gsec_wipe(ctx, sizeof *ctx);
    return result;
  }

  gsec_wipe(&outer, sizeof outer);
  outer.hash = ctx->hash;
  result = alg->init(inner_of(&outer));
  if (result == GSEC_OK) {
    result = alg->update(inner_of(&outer), opad, block_len);
  }
  if (result == GSEC_OK) {
    result = alg->update(inner_of(&outer), inner, digest_len);
  }
  if (result == GSEC_OK) {
    result = alg->final(inner_of(&outer), out);
  }
  gsec_wipe(inner, sizeof inner);
  gsec_wipe(opad, sizeof opad);
  gsec_wipe(&outer, sizeof outer);
  gsec_wipe(ctx, sizeof *ctx);
  return result;
}

GSEC_Result gsec_hmac(uint32_t hash, const void * key, size_t key_len,
    const void * data, size_t n, unsigned char * out) {
  GSEC_Hmac ctx;
  GSEC_Result result;

  result = gsec_hmac_init(&ctx, hash, key, key_len);
  if (result != GSEC_OK) {
    gsec_wipe(&ctx, sizeof ctx);
    return result;
  }
  result = gsec_hmac_update(&ctx, data, n);
  if (result != GSEC_OK) {
    gsec_wipe(&ctx, sizeof ctx);
    return result;
  }
  result = gsec_hmac_final(&ctx, out);
  if (result != GSEC_OK) {
    gsec_wipe(&ctx, sizeof ctx);
  }
  return result;
}

GSEC_Result gsec_hmac_verify(uint32_t hash, const void * key, size_t key_len,
    const void * data, size_t n, const void * mac, size_t mac_len) {
  const struct alg * alg;
  unsigned char got[GSEC_SHA512_DIGEST_LEN];
  GSEC_Result result;

  alg = find_alg(hash);
  if (alg == NULL || mac == NULL || mac_len != alg->digest_len) {
    return GSEC_ERR_INVALID;
  }
  result = gsec_hmac(hash, key, key_len, data, n, got);
  if (result != GSEC_OK) {
    gsec_wipe(got, sizeof got);
    return result;
  }
  result = gsec_equal(got, mac, mac_len);
  gsec_wipe(got, sizeof got);
  return result;
}
