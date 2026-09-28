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
 * Encrypt with RC2.
 *
 * `rc2 ecb|cbc <effective-bits> <hexkey> <hexiv|-> <hexmsg>`
 * ECB expects `-` for the vector. The message length is a multiple of
 * the block. Prints lowercase hex and a newline. This cipher is broken.
 * A new cipher is AES-GCM or ChaCha20-Poly1305.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/rc2.h>
#include <ghoti.io/security/secret.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MSG_MAX 4096u

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
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
  unsigned char key[GSEC_RC2_KEY_MAX];
  unsigned char iv[GSEC_RC2_BLOCK_LEN];
  unsigned char msg[MSG_MAX];
  unsigned char out[MSG_MAX];
  size_t key_len = 0;
  size_t iv_len = 0;
  size_t msg_len = 0;
  size_t i;
  unsigned long bits;
  char * end;
  int cbc;
  GSEC_Result result;
  static const char hex[] = "0123456789abcdef";

  if (argc != 6) {
    fprintf(stderr,
        "usage: rc2 ecb|cbc <effective-bits> <hexkey> <hexiv|-> <hexmsg>\n");
    return 2;
  }
  cbc = strcmp(argv[1], "cbc") == 0;
  if (!cbc && strcmp(argv[1], "ecb") != 0) {
    return 2;
  }
  bits = strtoul(argv[2], &end, 10);
  if (*end != '\0' || bits < GSEC_RC2_EFFECTIVE_MIN ||
      bits > GSEC_RC2_EFFECTIVE_MAX) {
    return 2;
  }
  if (!parse_bytes(argv[3], key, sizeof key, &key_len) || key_len < 1 ||
      !parse_bytes(argv[4], iv, sizeof iv, &iv_len) ||
      !parse_bytes(argv[5], msg, sizeof msg, &msg_len) ||
      (msg_len % GSEC_RC2_BLOCK_LEN) != 0 ||
      (cbc ? iv_len != GSEC_RC2_BLOCK_LEN : iv_len != 0) ||
      (!cbc && msg_len != GSEC_RC2_BLOCK_LEN)) {
    gsec_wipe(key, sizeof key);
    return 2;
  }
  if (cbc) {
    result = gsec_rc2_cbc_encrypt(key, key_len, (uint32_t)bits, iv,
        msg_len == 0 ? NULL : msg, msg_len, msg_len == 0 ? NULL : out);
  } else {
    result = gsec_rc2_encrypt(key, key_len, (uint32_t)bits, msg, out);
  }
  gsec_wipe(key, sizeof key);
  gsec_wipe(iv, sizeof iv);
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
