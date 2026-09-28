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
 * The PHC string for Argon2. Standard base64, padding omitted. A missing
 * version field is version 0x10.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/argon2.h>
#include <ghoti.io/security/secret.h>

#include <string.h>

#define SALT_MAX 256u

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_value(char c) {
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  }
  if (c >= 'a' && c <= 'z') {
    return c - 'a' + 26;
  }
  if (c >= '0' && c <= '9') {
    return c - '0' + 52;
  }
  if (c == '+') {
    return 62;
  }
  if (c == '/') {
    return 63;
  }
  return -1;
}

static GSEC_Result b64_encode(char * out, size_t cap, size_t * used,
    const unsigned char * in, size_t n) {
  size_t i = 0;
  size_t o = *used;

  while (i < n) {
    unsigned value = (unsigned)in[i++] << 16;
    unsigned parts = 2;

    if (i < n) {
      value |= (unsigned)in[i++] << 8;
      parts = 3;
    }
    if (i < n) {
      value |= in[i++];
      parts = 4;
    }
    if (o + parts > cap) {
      return GSEC_ERR_LIMIT;
    }
    out[o++] = B64[(value >> 18) & 63u];
    out[o++] = B64[(value >> 12) & 63u];
    if (parts > 2) {
      out[o++] = B64[(value >> 6) & 63u];
    }
    if (parts > 3) {
      out[o++] = B64[value & 63u];
    }
  }
  *used = o;
  return GSEC_OK;
}

static GSEC_Result b64_decode(const char * text, size_t n, unsigned char * out,
    size_t cap, size_t * out_len) {
  unsigned value = 0;
  unsigned bits = 0;
  size_t o = 0;
  size_t i;

  for (i = 0; i < n; i++) {
    int digit = b64_value(text[i]);

    if (digit < 0) {
      return GSEC_ERR_CORRUPT;
    }
    value = (value << 6) | (unsigned)digit;
    bits += 6u;
    if (bits >= 8u) {
      bits -= 8u;
      if (o >= cap) {
        return GSEC_ERR_LIMIT;
      }
      out[o++] = (unsigned char)((value >> bits) & 0xffu);
    }
  }
  if (bits >= 6u) {
    return GSEC_ERR_CORRUPT;
  }
  *out_len = o;
  return GSEC_OK;
}

static GSEC_Result append(char * out, size_t cap, size_t * used, const char * text) {
  size_t n = strlen(text);

  if (*used + n > cap) {
    return GSEC_ERR_LIMIT;
  }
  memcpy(out + *used, text, n);
  *used += n;
  return GSEC_OK;
}

static GSEC_Result append_u32(char * out, size_t cap, size_t * used, uint32_t value) {
  char digits[10];
  unsigned n = 0;
  uint32_t rest = value;

  do {
    digits[n++] = (char)('0' + (rest % 10u));
    rest /= 10u;
  } while (rest != 0);
  if (*used + n > cap) {
    return GSEC_ERR_LIMIT;
  }
  while (n > 0) {
    out[(*used)++] = digits[--n];
  }
  return GSEC_OK;
}

GSEC_Result gsec_argon2_phc(uint32_t version, uint32_t type,
    const void * password, size_t password_len, const void * salt,
    size_t salt_len, const void * secret, size_t secret_len, const void * ad,
    size_t ad_len, uint32_t memory_kib, uint32_t passes, uint32_t lanes,
    size_t tag_len, void * encoded, size_t encoded_cap, size_t * encoded_len) {
  unsigned char tag[GSEC_ARGON2_TAG_MAX];
  char * out;
  size_t used = 0;
  const char * name;
  GSEC_Result result;

  if (encoded == NULL || encoded_len == NULL || encoded_cap == 0) {
    return GSEC_ERR_INVALID;
  }
  if (type == GSEC_ARGON2_D) {
    name = "$argon2d$";
  } else if (type == GSEC_ARGON2_I) {
    name = "$argon2i$";
  } else if (type == GSEC_ARGON2_ID) {
    name = "$argon2id$";
  } else {
    return GSEC_ERR_INVALID;
  }
  if (tag_len < GSEC_ARGON2_TAG_MIN || tag_len > GSEC_ARGON2_TAG_MAX) {
    return GSEC_ERR_INVALID;
  }
  result = gsec_argon2_version(version, type, password, password_len, salt,
      salt_len, secret, secret_len, ad, ad_len, memory_kib, passes, lanes, tag,
      tag_len);
  if (result != GSEC_OK) {
    return result;
  }
  out = (char *)encoded;
  result = append(out, encoded_cap - 1u, &used, name);
  if (result == GSEC_OK) {
    result = append(out, encoded_cap - 1u, &used, "v=");
  }
  if (result == GSEC_OK) {
    result = append_u32(out, encoded_cap - 1u, &used, version);
  }
  if (result == GSEC_OK) {
    result = append(out, encoded_cap - 1u, &used, "$m=");
  }
  if (result == GSEC_OK) {
    result = append_u32(out, encoded_cap - 1u, &used, memory_kib);
  }
  if (result == GSEC_OK) {
    result = append(out, encoded_cap - 1u, &used, ",t=");
  }
  if (result == GSEC_OK) {
    result = append_u32(out, encoded_cap - 1u, &used, passes);
  }
  if (result == GSEC_OK) {
    result = append(out, encoded_cap - 1u, &used, ",p=");
  }
  if (result == GSEC_OK) {
    result = append_u32(out, encoded_cap - 1u, &used, lanes);
  }
  if (result == GSEC_OK) {
    result = append(out, encoded_cap - 1u, &used, "$");
  }
  if (result == GSEC_OK) {
    result = b64_encode(out, encoded_cap - 1u, &used,
        (const unsigned char *)salt, salt_len);
  }
  if (result == GSEC_OK) {
    result = append(out, encoded_cap - 1u, &used, "$");
  }
  if (result == GSEC_OK) {
    result = b64_encode(out, encoded_cap - 1u, &used, tag, tag_len);
  }
  gsec_wipe(tag, sizeof tag);
  if (result != GSEC_OK) {
    gsec_wipe(encoded, encoded_cap);
    return result;
  }
  out[used] = 0;
  *encoded_len = used;
  return GSEC_OK;
}

static int take(const char ** p, size_t * left, const char * literal) {
  size_t n = strlen(literal);
  size_t i;

  if (*left < n) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    if ((*p)[i] != literal[i]) {
      return 0;
    }
  }
  *p += n;
  *left -= n;
  return 1;
}

static int take_u32(const char ** p, size_t * left, uint32_t * out) {
  uint32_t value = 0;
  int any = 0;

  if (*left == 0 || **p < '0' || **p > '9') {
    return 0;
  }
  while (*left != 0 && **p >= '0' && **p <= '9') {
    uint32_t digit = (uint32_t)(**p - '0');

    if (value > (UINT32_MAX - digit) / 10u) {
      return 0;
    }
    value = value * 10u + digit;
    (*p)++;
    (*left)--;
    any = 1;
  }
  if (!any) {
    return 0;
  }
  *out = value;
  return 1;
}

GSEC_Result gsec_argon2_phc_verify(const void * encoded, size_t encoded_len,
    const void * password, size_t password_len, const void * secret,
    size_t secret_len, const void * ad, size_t ad_len) {
  const char * p;
  size_t left;
  uint32_t version = GSEC_ARGON2_VERSION_10;
  uint32_t type;
  uint32_t memory_kib = 0;
  uint32_t passes = 0;
  uint32_t lanes = 0;
  unsigned char salt[SALT_MAX];
  unsigned char want[GSEC_ARGON2_TAG_MAX];
  unsigned char got[GSEC_ARGON2_TAG_MAX];
  size_t salt_len = 0;
  size_t want_len = 0;
  const char * salt_text;
  size_t salt_text_len;
  const char * tag_text;
  size_t tag_text_len;
  GSEC_Result result;

  if (encoded == NULL || encoded_len == 0 ||
      (password == NULL && password_len != 0) ||
      (secret == NULL && secret_len != 0) ||
      (ad == NULL && ad_len != 0)) {
    return GSEC_ERR_INVALID;
  }
  p = (const char *)encoded;
  left = encoded_len;
  if (take(&p, &left, "$argon2id$")) {
    type = GSEC_ARGON2_ID;
  } else if (take(&p, &left, "$argon2i$")) {
    type = GSEC_ARGON2_I;
  } else if (take(&p, &left, "$argon2d$")) {
    type = GSEC_ARGON2_D;
  } else {
    return GSEC_ERR_CORRUPT;
  }
  if (left >= 2 && p[0] == 'v' && p[1] == '=') {
    p += 2;
    left -= 2;
    if (!take_u32(&p, &left, &version) || !take(&p, &left, "$")) {
      return GSEC_ERR_CORRUPT;
    }
  }
  if (!take(&p, &left, "m=") || !take_u32(&p, &left, &memory_kib) ||
      !take(&p, &left, ",t=") || !take_u32(&p, &left, &passes) ||
      !take(&p, &left, ",p=") || !take_u32(&p, &left, &lanes) ||
      !take(&p, &left, "$")) {
    return GSEC_ERR_CORRUPT;
  }
  salt_text = p;
  salt_text_len = 0;
  while (salt_text_len < left && p[salt_text_len] != '$') {
    salt_text_len++;
  }
  if (salt_text_len == 0 || salt_text_len == left) {
    return GSEC_ERR_CORRUPT;
  }
  p += salt_text_len + 1u;
  left -= salt_text_len + 1u;
  tag_text = p;
  tag_text_len = left;
  if (tag_text_len == 0) {
    return GSEC_ERR_CORRUPT;
  }
  result = b64_decode(salt_text, salt_text_len, salt, sizeof salt, &salt_len);
  if (result != GSEC_OK) {
    return result;
  }
  result = b64_decode(tag_text, tag_text_len, want, sizeof want, &want_len);
  if (result != GSEC_OK) {
    gsec_wipe(salt, sizeof salt);
    return result;
  }
  if (want_len < GSEC_ARGON2_TAG_MIN || want_len > GSEC_ARGON2_TAG_MAX) {
    gsec_wipe(salt, sizeof salt);
    gsec_wipe(want, sizeof want);
    return GSEC_ERR_CORRUPT;
  }
  result = gsec_argon2_version(version, type, password, password_len, salt,
      salt_len, secret, secret_len, ad, ad_len, memory_kib, passes, lanes, got,
      want_len);
  gsec_wipe(salt, sizeof salt);
  if (result != GSEC_OK) {
    gsec_wipe(want, sizeof want);
    gsec_wipe(got, sizeof got);
    return result;
  }
  result = gsec_equal(got, want, want_len);
  gsec_wipe(want, sizeof want);
  gsec_wipe(got, sizeof got);
  return result;
}
