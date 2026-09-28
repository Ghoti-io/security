/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * Ask the image's libxcrypt for one bcrypt modular-crypt string.
 *
 * `crypt-bcrypt <hexpass|-> <setting>`
 * The setting is `$2a$` or `$2b$`, the cost, and the 22-character salt.
 * A dash is an empty password. Prints the crypt string.
 */

#include <crypt.h>

#include <stdio.h>
#include <string.h>

static int nibble(char c) {
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

int main(int argc, char ** argv) {
  unsigned char pass[73];
  size_t n = 0;
  size_t i;
  struct crypt_data data;
  char * out;

  if (argc != 3) {
    return 2;
  }
  if (strcmp(argv[1], "-") != 0) {
    size_t len = strlen(argv[1]);

    if ((len % 2u) != 0 || len / 2u > 72) {
      return 2;
    }
    n = len / 2u;
    for (i = 0; i < n; i++) {
      int hi = nibble(argv[1][i * 2u]);
      int lo = nibble(argv[1][i * 2u + 1u]);

      if (hi < 0 || lo < 0) {
        return 2;
      }
      pass[i] = (unsigned char)((hi << 4) | lo);
      if (pass[i] == 0) {
        return 2;
      }
    }
  }
  pass[n] = 0;
  memset(&data, 0, sizeof data);
  out = crypt_r((char *)pass, argv[2], &data);
  memset(pass, 0, sizeof pass);
  if (out == NULL || out[0] == '*') {
    return 1;
  }
  if (puts(out) == EOF) {
    return 1;
  }
  return 0;
}
