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
 * X25519 on the command line.
 *
 * `x25519 <hexscalar> <hexpoint>` prints the shared secret. `x25519 public
 * <hexscalar>` prints the public key. A scalar or a u-coordinate that is
 * not 32 bytes exits 1 and prints nothing, as does the all-zero shared
 * secret.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/x25519.h>

#include <stdio.h>
#include <string.h>

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

static int parse_hex(const char * text, unsigned char * out, size_t cap,
    size_t * n) {
  size_t len;
  size_t i;

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

static int write_hex(const unsigned char * p, size_t n) {
  static const char hex[] = "0123456789abcdef";
  size_t i;

  for (i = 0; i < n; i++) {
    char pair[2];
    pair[0] = hex[p[i] >> 4];
    pair[1] = hex[p[i] & 0x0fu];
    if (fwrite(pair, 1, 2, stdout) != 2) {
      return 0;
    }
  }
  return fputc('\n', stdout) != EOF;
}

int main(int argc, char ** argv) {
  unsigned char scalar[GSEC_X25519_LEN];
  unsigned char point[GSEC_X25519_LEN];
  unsigned char out[GSEC_X25519_LEN];
  size_t n = 0;
  int public_key;
  GSEC_Result result;

  public_key = argc == 3 && strcmp(argv[1], "public") == 0;
  if (!public_key && argc != 3) {
    fprintf(stderr, "usage: x25519 hexscalar hexpoint | x25519 public hexscalar\n");
    return 2;
  }
  if (!parse_hex(public_key ? argv[2] : argv[1], scalar, sizeof scalar, &n)) {
    return 2;
  }
  if (n != GSEC_X25519_LEN) {
    gsec_wipe(scalar, sizeof scalar);
    return 1;
  }
  if (!public_key) {
    if (!parse_hex(argv[2], point, sizeof point, &n)) {
      gsec_wipe(scalar, sizeof scalar);
      return 2;
    }
    if (n != GSEC_X25519_LEN) {
      gsec_wipe(scalar, sizeof scalar);
      gsec_wipe(point, sizeof point);
      return 1;
    }
  }
  result = public_key ? gsec_x25519_public(scalar, out)
      : gsec_x25519(scalar, point, out);
  gsec_wipe(scalar, sizeof scalar);
  gsec_wipe(point, sizeof point);
  if (result != GSEC_OK || !write_hex(out, sizeof out)) {
    gsec_wipe(out, sizeof out);
    return 1;
  }
  gsec_wipe(out, sizeof out);
  return 0;
}
