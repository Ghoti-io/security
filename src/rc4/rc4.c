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
 * RC4. The state permutation is indexed by bytes that depend on the key.
 * That is the cipher, and it is why this file is not in the constant-time
 * gate.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/rc4.h>
#include <ghoti.io/security/secret.h>

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

GSEC_Result gsec_rc4(const void * key, size_t key_len, const void * in,
    size_t len, void * out) {
  unsigned char s[256];
  const unsigned char * k;
  const unsigned char * src;
  unsigned char * dst;
  unsigned i;
  unsigned j;
  size_t n;

  if (key == NULL || key_len < GSEC_RC4_KEY_MIN || key_len > GSEC_RC4_KEY_MAX) {
    return GSEC_ERR_INVALID;
  }
  if (len == 0) {
    return GSEC_OK;
  }
  if (in == NULL || out == NULL) {
    return GSEC_ERR_INVALID;
  }
  src = (const unsigned char *)in;
  dst = (unsigned char *)out;
  if (partial_overlap(src, dst, len)) {
    return GSEC_ERR_INVALID;
  }
  k = (const unsigned char *)key;
  for (i = 0; i < 256u; i++) {
    s[i] = (unsigned char)i;
  }
  j = 0;
  for (i = 0; i < 256u; i++) {
    unsigned char tmp;

    j = (j + s[i] + k[i % key_len]) & 255u;
    tmp = s[i];
    s[i] = s[j];
    s[j] = tmp;
  }
  i = 0;
  j = 0;
  for (n = 0; n < len; n++) {
    unsigned char tmp;
    unsigned t;

    i = (i + 1u) & 255u;
    j = (j + s[i]) & 255u;
    tmp = s[i];
    s[i] = s[j];
    s[j] = tmp;
    t = (s[i] + s[j]) & 255u;
    dst[n] = (unsigned char)(src[n] ^ s[t]);
  }
  gsec_wipe(s, sizeof s);
  return GSEC_OK;
}
