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
 * P-384 ECDH on the command line.
 *
 * `ecdh_p384 public <hexscalar>` prints 04 followed by the public key.
 * `ecdh_p384 <hexscalar> <hexpeer>` prints the shared x coordinate. The
 * peer is 97 bytes starting with 04, or 96 bytes of x then y.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/ecdh_p384.h>
#include <ghoti.io/security/secret.h>

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

static int load_scalar(const char * text, unsigned char out[GSEC_P384_LEN]) {
  unsigned char raw[64];
  size_t len;
  size_t n;
  size_t i;

  len = strlen(text);
  if ((len % 2u) != 0) {
    return 2;
  }
  n = len / 2u;
  if (n == 0 || n > sizeof raw) {
    return 1;
  }
  for (i = 0; i < n; i++) {
    int hi = hex_nibble(text[i * 2u]);
    int lo = hex_nibble(text[i * 2u + 1u]);
    if (hi < 0 || lo < 0) {
      return 2;
    }
    raw[i] = (unsigned char)((hi << 4) | lo);
  }
  if (n == 49) {
    if (raw[0] != 0) {
      gsec_wipe(raw, sizeof raw);
      return 1;
    }
    memcpy(out, raw + 1, GSEC_P384_LEN);
  } else if (n > 48) {
    gsec_wipe(raw, sizeof raw);
    return 1;
  } else {
    memset(out, 0, GSEC_P384_LEN);
    memcpy(out + (GSEC_P384_LEN - n), raw, n);
  }
  gsec_wipe(raw, sizeof raw);
  return 0;
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
  unsigned char scalar[GSEC_P384_LEN];
  unsigned char peer_raw[97];
  unsigned char peer[GSEC_P384_PUBLIC_LEN];
  unsigned char out[GSEC_P384_PUBLIC_LEN];
  size_t n = 0;
  int public_key;
  int loaded;
  GSEC_Result result;

  public_key = argc == 3 && strcmp(argv[1], "public") == 0;
  if (!public_key && argc != 3) {
    fprintf(stderr,
        "usage: ecdh_p384 hexscalar hexpeer | ecdh_p384 public hexscalar\n");
    return 2;
  }
  loaded = load_scalar(public_key ? argv[2] : argv[1], scalar);
  if (loaded != 0) {
    return loaded;
  }
  if (!public_key) {
    if (!parse_hex(argv[2], peer_raw, sizeof peer_raw, &n)) {
      gsec_wipe(scalar, sizeof scalar);
      return 2;
    }
    if (n == 97 && peer_raw[0] == 0x04) {
      memcpy(peer, peer_raw + 1, GSEC_P384_PUBLIC_LEN);
    } else if (n == 96) {
      memcpy(peer, peer_raw, GSEC_P384_PUBLIC_LEN);
    } else {
      gsec_wipe(scalar, sizeof scalar);
      gsec_wipe(peer_raw, sizeof peer_raw);
      return 1;
    }
  }
  result = public_key ? gsec_ecdh_p384_public(scalar, out)
      : gsec_ecdh_p384(scalar, peer, out);
  gsec_wipe(scalar, sizeof scalar);
  gsec_wipe(peer, sizeof peer);
  gsec_wipe(peer_raw, sizeof peer_raw);
  if (result != GSEC_OK) {
    gsec_wipe(out, sizeof out);
    return 1;
  }
  if (public_key) {
    unsigned char tagged[97];
    int wrote;

    tagged[0] = 0x04;
    memcpy(tagged + 1, out, GSEC_P384_PUBLIC_LEN);
    wrote = write_hex(tagged, sizeof tagged);
    gsec_wipe(tagged, sizeof tagged);
    gsec_wipe(out, sizeof out);
    return wrote ? 0 : 1;
  }
  if (!write_hex(out, GSEC_P384_LEN)) {
    gsec_wipe(out, sizeof out);
    return 1;
  }
  gsec_wipe(out, sizeof out);
  return 0;
}
