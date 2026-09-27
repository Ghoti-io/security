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
 * Encrypt or decrypt with RC4.
 *
 * `rc4 <hexkey> <hexmsg>`. Prints lowercase hex and a newline. An empty
 * message is an empty hex string. `make check-oracle` compares it with
 * OpenSSL's legacy RC4.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/rc4.h>
#include <ghoti.io/security/secret.h>

#include <stdio.h>
#include <string.h>

#define MSG_MAX 4096u

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

static int parse_var(const char * text, unsigned char * out, size_t cap,
    size_t * n) {
  size_t len = strlen(text);
  size_t i;

  if ((len % 2u) != 0 || len / 2u > cap || len == 0) {
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
  unsigned char key[GSEC_RC4_KEY_MAX];
  unsigned char msg[MSG_MAX];
  unsigned char out[MSG_MAX];
  size_t key_len = 0;
  size_t msg_len = 0;
  size_t i;
  GSEC_Result result;
  static const char hex[] = "0123456789abcdef";

  if (argc != 3) {
    fprintf(stderr, "usage: rc4 hexkey hexmsg\n");
    return 2;
  }
  if (!parse_var(argv[1], key, GSEC_RC4_KEY_MAX, &key_len)) {
    return 2;
  }
  if (strlen(argv[2]) == 0) {
    msg_len = 0;
  } else if (!parse_var(argv[2], msg, MSG_MAX, &msg_len)) {
    return 2;
  }
  result = gsec_rc4(key, key_len, msg_len == 0 ? NULL : msg, msg_len,
      msg_len == 0 ? NULL : out);
  gsec_wipe(key, sizeof key);
  gsec_wipe(msg, sizeof msg);
  if (result != GSEC_OK) {
    gsec_wipe(out, sizeof out);
    return 1;
  }
  for (i = 0; i < msg_len; i++) {
    unsigned char pair[2];

    pair[0] = (unsigned char)hex[out[i] >> 4];
    pair[1] = (unsigned char)hex[out[i] & 0x0fu];
    if (fwrite(pair, 1, 2, stdout) != 2) {
      gsec_wipe(out, sizeof out);
      return 1;
    }
  }
  gsec_wipe(out, sizeof out);
  if (fputc('\n', stdout) == EOF) {
    return 1;
  }
  return 0;
}
