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
 * Derive a key with PBKDF2 and print it in hex.
 *
 * `pbkdf2 sha1 <hexpass> <hexsalt> <iterations> <outlen>`. A field of `-`
 * is empty. `make check-oracle` runs this against the pinned OpenSSL.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/pbkdf2.h>
#include <ghoti.io/security/secret.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FIELD 1024
#define MAX_OUT 1024

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

static int parse_field(const char * text, unsigned char * out, size_t * n_out) {
  size_t len;
  size_t i;

  if (strcmp(text, "-") == 0) {
    *n_out = 0;
    return 1;
  }
  len = strlen(text);
  if (len % 2 != 0 || len / 2 > MAX_FIELD) {
    return 0;
  }
  for (i = 0; i < len; i += 2) {
    int hi = hex_nibble(text[i]);
    int lo = hex_nibble(text[i + 1]);
    if (hi < 0 || lo < 0) {
      return 0;
    }
    out[i / 2] = (unsigned char)((hi << 4) | lo);
  }
  *n_out = len / 2;
  return 1;
}

static uint32_t hash_id(const char * name) {
  if (strcmp(name, "sha1") == 0) {
    return GSEC_PBKDF2_SHA1;
  }
  if (strcmp(name, "sha256") == 0) {
    return GSEC_PBKDF2_SHA256;
  }
  if (strcmp(name, "sha384") == 0) {
    return GSEC_PBKDF2_SHA384;
  }
  if (strcmp(name, "sha512") == 0) {
    return GSEC_PBKDF2_SHA512;
  }
  return 0;
}

static int parse_u32(const char * text, uint32_t * out) {
  char * end = NULL;
  unsigned long value;

  errno = 0;
  value = strtoul(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value > 0xfffffffful) {
    return 0;
  }
  *out = (uint32_t)value;
  return 1;
}

int main(int argc, char ** argv) {
  unsigned char password[MAX_FIELD];
  unsigned char salt[MAX_FIELD];
  unsigned char dk[MAX_OUT];
  size_t password_len = 0;
  size_t salt_len = 0;
  size_t out_len = 0;
  uint32_t hash;
  uint32_t iterations = 0;
  char * end = NULL;
  unsigned long value;
  size_t i;
  GSEC_Result result;

  if (argc != 6) {
    fprintf(stderr,
        "usage: pbkdf2 sha1|sha256|sha384|sha512 hexpass hexsalt iterations outlen\n");
    return 2;
  }
  hash = hash_id(argv[1]);
  if (hash == 0 || !parse_field(argv[2], password, &password_len) ||
      !parse_field(argv[3], salt, &salt_len) ||
      !parse_u32(argv[4], &iterations)) {
    return 2;
  }
  errno = 0;
  value = strtoul(argv[5], &end, 10);
  if (errno != 0 || end == argv[5] || *end != '\0' || value > MAX_OUT) {
    gsec_wipe(password, sizeof password);
    gsec_wipe(salt, sizeof salt);
    return 2;
  }
  out_len = (size_t)value;
  result = gsec_pbkdf2(hash, password_len == 0 ? NULL : password, password_len,
      salt_len == 0 ? NULL : salt, salt_len, iterations,
      out_len == 0 ? NULL : dk, out_len);
  gsec_wipe(password, sizeof password);
  gsec_wipe(salt, sizeof salt);
  if (result != GSEC_OK) {
    gsec_wipe(dk, sizeof dk);
    return 1;
  }
  for (i = 0; i < out_len; i++) {
    printf("%02x", dk[i]);
  }
  printf("\n");
  gsec_wipe(dk, sizeof dk);
  return 0;
}
