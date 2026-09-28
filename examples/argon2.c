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
 * Hash a password with Argon2.
 *
 * `argon2 <d|i|id> <hexpass|-> <hexsalt> <memory_kib> <passes> <lanes> <taglen>
 * [hexsecret|- hexad|-]`
 * A dash is empty. Secret and associated data are omitted when those two
 * arguments are absent. Prints lowercase hex and a newline.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/argon2.h>
#include <ghoti.io/security/secret.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PASS_MAX 256u
#define SALT_MAX 256u

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

static int parse_bytes(const char * text, unsigned char * out, size_t cap,
    size_t * n) {
  size_t len;
  size_t i;

  if (strcmp(text, "-") == 0) {
    *n = 0;
    return 1;
  }
  len = strlen(text);
  if ((len % 2u) != 0 || len / 2u > cap) {
    return 0;
  }
  *n = len / 2u;
  for (i = 0; i < *n; i++) {
    int hi = hex_nibble(text[i * 2u]);
    int lo = hex_nibble(text[i * 2u + 1u]);
    if (hi < 0 || lo < 0) {
      return 0;
    }
    out[i] = (unsigned char)((hi << 4) | lo);
  }
  return 1;
}

int main(int argc, char ** argv) {
  unsigned char password[PASS_MAX];
  unsigned char salt[SALT_MAX];
  unsigned char secret[SALT_MAX];
  unsigned char ad[SALT_MAX];
  unsigned char tag[GSEC_ARGON2_TAG_MAX];
  size_t password_len = 0;
  size_t salt_len = 0;
  size_t secret_len = 0;
  size_t ad_len = 0;
  unsigned long memory_kib;
  unsigned long passes;
  unsigned long lanes;
  unsigned long tag_len;
  uint32_t type;
  size_t i;
  char * end;
  GSEC_Result result;
  static const char hex[] = "0123456789abcdef";

  if (argc != 8 && argc != 10) {
    fprintf(stderr,
        "usage: argon2 d|i|id hexpass|- hexsalt memory passes lanes taglen"
        " [hexsecret|- hexad|-]\n");
    return 2;
  }
  if (strcmp(argv[1], "d") == 0) {
    type = GSEC_ARGON2_D;
  } else if (strcmp(argv[1], "i") == 0) {
    type = GSEC_ARGON2_I;
  } else if (strcmp(argv[1], "id") == 0) {
    type = GSEC_ARGON2_ID;
  } else {
    return 2;
  }
  if (!parse_bytes(argv[2], password, PASS_MAX, &password_len) ||
      !parse_bytes(argv[3], salt, SALT_MAX, &salt_len)) {
    return 2;
  }
  if (argc == 10 &&
      (!parse_bytes(argv[8], secret, SALT_MAX, &secret_len) ||
      !parse_bytes(argv[9], ad, SALT_MAX, &ad_len))) {
    return 2;
  }
  memory_kib = strtoul(argv[4], &end, 10);
  if (*end != '\0' || memory_kib > UINT32_MAX) {
    return 2;
  }
  passes = strtoul(argv[5], &end, 10);
  if (*end != '\0' || passes == 0 || passes > UINT32_MAX) {
    return 2;
  }
  lanes = strtoul(argv[6], &end, 10);
  if (*end != '\0' || lanes == 0 || lanes > UINT32_MAX) {
    return 2;
  }
  tag_len = strtoul(argv[7], &end, 10);
  if (*end != '\0' || tag_len > sizeof tag) {
    return 2;
  }
  result = gsec_argon2(type, password_len == 0 ? NULL : password,
      password_len, salt, salt_len, secret_len == 0 ? NULL : secret,
      secret_len, ad_len == 0 ? NULL : ad, ad_len, (uint32_t)memory_kib,
      (uint32_t)passes, (uint32_t)lanes, tag, tag_len);
  gsec_wipe(password, sizeof password);
  gsec_wipe(salt, sizeof salt);
  gsec_wipe(secret, sizeof secret);
  gsec_wipe(ad, sizeof ad);
  if (result != GSEC_OK) {
    gsec_wipe(tag, sizeof tag);
    return 1;
  }
  for (i = 0; i < tag_len; i++) {
    unsigned char pair[2];

    pair[0] = (unsigned char)hex[tag[i] >> 4];
    pair[1] = (unsigned char)hex[tag[i] & 0x0fu];
    if (fwrite(pair, 1, 2, stdout) != 2) {
      gsec_wipe(tag, sizeof tag);
      return 1;
    }
  }
  gsec_wipe(tag, sizeof tag);
  if (fputc('\n', stdout) == EOF) {
    return 1;
  }
  return 0;
}
