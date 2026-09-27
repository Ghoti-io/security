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
 * HKDF is extract then expand, and both steps are HMAC. The hash id, the
 * lengths, and the block counter are public. The bytes of the IKM, the salt,
 * the PRK, and the output are not a branch condition.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/hkdf.h>
#include <ghoti.io/security/secret.h>

static size_t digest_len(uint32_t hash) {
  if (hash == GSEC_HKDF_SHA1) {
    return GSEC_SHA1_DIGEST_LEN;
  }
  if (hash == GSEC_HKDF_SHA256) {
    return GSEC_SHA256_DIGEST_LEN;
  }
  if (hash == GSEC_HKDF_SHA384) {
    return GSEC_SHA384_DIGEST_LEN;
  }
  if (hash == GSEC_HKDF_SHA512) {
    return GSEC_SHA512_DIGEST_LEN;
  }
  return 0;
}

static void copy_bytes(unsigned char * dst, const unsigned char * src, size_t n) {
  size_t i;

  for (i = 0; i < n; i++) {
    dst[i] = src[i];
  }
}

GSEC_Result gsec_hkdf_extract(uint32_t hash, const void * salt, size_t salt_len,
    const void * ikm, size_t ikm_len, unsigned char * prk) {
  unsigned char zeros[GSEC_SHA512_DIGEST_LEN];
  const void * salt_use;
  size_t salt_use_len;
  size_t dig;
  GSEC_Result result;

  dig = digest_len(hash);
  if (dig == 0 || prk == NULL || (salt == NULL && salt_len > 0) ||
      (ikm == NULL && ikm_len > 0)) {
    return GSEC_ERR_INVALID;
  }
  gsec_wipe(zeros, sizeof zeros);
  if (salt_len == 0) {
    salt_use = zeros;
    salt_use_len = dig;
  } else {
    salt_use = salt;
    salt_use_len = salt_len;
  }
  result = gsec_hmac(hash, salt_use, salt_use_len, ikm, ikm_len, prk);
  gsec_wipe(zeros, sizeof zeros);
  if (result != GSEC_OK) {
    gsec_wipe(prk, dig);
  }
  return result;
}

GSEC_Result gsec_hkdf_expand(uint32_t hash, const void * prk, size_t prk_len,
    const void * info, size_t info_len, unsigned char * okm, size_t okm_len) {
  unsigned char prev[GSEC_SHA512_DIGEST_LEN];
  unsigned char block[GSEC_SHA512_DIGEST_LEN];
  GSEC_Hmac ctx;
  size_t dig;
  size_t nblocks;
  size_t filled;
  size_t i;
  GSEC_Result result;

  dig = digest_len(hash);
  if (dig == 0 || (prk == NULL && prk_len > 0) ||
      (info == NULL && info_len > 0) || (okm == NULL && okm_len > 0)) {
    return GSEC_ERR_INVALID;
  }
  if (okm_len == 0) {
    return GSEC_OK;
  }
  if (okm_len > 255u * dig) {
    return GSEC_ERR_LIMIT;
  }
  nblocks = (okm_len + dig - 1u) / dig;
  gsec_wipe(prev, sizeof prev);
  filled = 0;
  for (i = 1; i <= nblocks; i++) {
    unsigned char counter;
    size_t take;

    result = gsec_hmac_init(&ctx, hash, prk, prk_len);
    if (result == GSEC_OK && i > 1) {
      result = gsec_hmac_update(&ctx, prev, dig);
    }
    if (result == GSEC_OK && info_len > 0) {
      result = gsec_hmac_update(&ctx, info, info_len);
    }
    counter = (unsigned char)i;
    if (result == GSEC_OK) {
      result = gsec_hmac_update(&ctx, &counter, 1);
    }
    if (result == GSEC_OK) {
      result = gsec_hmac_final(&ctx, block);
    }
    if (result != GSEC_OK) {
      gsec_wipe(&ctx, sizeof ctx);
      gsec_wipe(prev, sizeof prev);
      gsec_wipe(block, sizeof block);
      gsec_wipe(okm, okm_len);
      return result;
    }
    take = okm_len - filled;
    if (take > dig) {
      take = dig;
    }
    copy_bytes(okm + filled, block, take);
    filled += take;
    copy_bytes(prev, block, dig);
  }
  gsec_wipe(prev, sizeof prev);
  gsec_wipe(block, sizeof block);
  return GSEC_OK;
}

GSEC_Result gsec_hkdf(uint32_t hash, const void * salt, size_t salt_len,
    const void * ikm, size_t ikm_len, const void * info, size_t info_len,
    unsigned char * okm, size_t okm_len) {
  unsigned char prk[GSEC_SHA512_DIGEST_LEN];
  size_t dig;
  GSEC_Result result;

  dig = digest_len(hash);
  if (dig == 0) {
    return GSEC_ERR_INVALID;
  }
  result = gsec_hkdf_extract(hash, salt, salt_len, ikm, ikm_len, prk);
  if (result != GSEC_OK) {
    gsec_wipe(prk, sizeof prk);
    return result;
  }
  result = gsec_hkdf_expand(hash, prk, dig, info, info_len, okm, okm_len);
  gsec_wipe(prk, sizeof prk);
  return result;
}
