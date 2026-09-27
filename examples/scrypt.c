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
 * Derive a key with scrypt.
 *
 * `scrypt <hexpass|-> <hexsalt|-> <n> <r> <p> <dklen>`
 * A dash is an empty password or salt. Prints lowercase hex and a newline.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/scrypt.h>
#include <ghoti.io/security/secret.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CAP 256u

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

static int parse_bytes(const char * text, unsigned char * out, size_t * n) {
  size_t len;
  size_t i;

  if (strcmp(text, "-") == 0) {
    *n = 0;
    return 1;
  }
  len = strlen(text);
  if ((len % 2u) != 0 || len / 2u > CAP) {
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
  unsigned char password[CAP];
  unsigned char salt[CAP];
  unsigned char dk[CAP];
  size_t password_len = 0;
  size_t salt_len = 0;
  unsigned long n;
  unsigned long r;
  unsigned long p;
  unsigned long dk_len;
  size_t i;
  char * end;
  GSEC_Result result;
  static const char hex[] = "0123456789abcdef";

  if (argc != 7) {
    fprintf(stderr, "usage: scrypt hexpass|- hexsalt|- n r p dklen\n");
    return 2;
  }
  if (!parse_bytes(argv[1], password, &password_len) ||
      !parse_bytes(argv[2], salt, &salt_len)) {
    return 2;
  }
  n = strtoul(argv[3], &end, 10);
  if (*end != '\0' || n < 2) {
    return 2;
  }
  r = strtoul(argv[4], &end, 10);
  if (*end != '\0' || r == 0 || r > UINT32_MAX) {
    return 2;
  }
  p = strtoul(argv[5], &end, 10);
  if (*end != '\0' || p == 0 || p > UINT32_MAX) {
    return 2;
  }
  dk_len = strtoul(argv[6], &end, 10);
  if (*end != '\0' || dk_len > CAP) {
    return 2;
  }
  result = gsec_scrypt(password_len == 0 ? NULL : password, password_len,
      salt_len == 0 ? NULL : salt, salt_len, n, (uint32_t)r, (uint32_t)p,
      dk_len == 0 ? NULL : dk, dk_len);
  gsec_wipe(password, sizeof password);
  gsec_wipe(salt, sizeof salt);
  if (result != GSEC_OK) {
    gsec_wipe(dk, sizeof dk);
    return 1;
  }
  for (i = 0; i < dk_len; i++) {
    unsigned char pair[2];

    pair[0] = (unsigned char)hex[dk[i] >> 4];
    pair[1] = (unsigned char)hex[dk[i] & 0x0fu];
    if (fwrite(pair, 1, 2, stdout) != 2) {
      gsec_wipe(dk, sizeof dk);
      return 1;
    }
  }
  gsec_wipe(dk, sizeof dk);
  if (fputc('\n', stdout) == EOF) {
    return 1;
  }
  return 0;
}
