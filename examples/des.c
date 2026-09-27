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
 * Encrypt or decrypt with DES or three-key Triple DES.
 *
 * `des ecb|cbc|ede3|ede3-cbc encrypt|decrypt <hexkey> <hexiv|-> <hexmsg>`
 * ECB ignores the vector and expects `-`. The message length is a
 * multiple of 8 bytes. Prints lowercase hex and a newline.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/des.h>
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

static int parse_exact(const char * text, unsigned char * out, size_t n) {
  size_t i;

  if (strcmp(text, "-") == 0) {
    return n == 0;
  }
  if (strlen(text) != n * 2u) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    int hi = hex_nibble(text[i * 2u]);
    int lo = hex_nibble(text[i * 2u + 1u]);
    if (hi < 0 || lo < 0) {
      return 0;
    }
    out[i] = (unsigned char)((hi << 4) | lo);
  }
  return 1;
}

static int parse_msg(const char * text, unsigned char * out, size_t * n) {
  size_t len = strlen(text);
  size_t i;

  if (len == 0) {
    *n = 0;
    return 1;
  }
  if ((len % 2u) != 0 || len / 2u > MSG_MAX || ((len / 2u) % 8u) != 0) {
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
  unsigned char key[GSEC_DES_EDE3_KEY_LEN];
  unsigned char iv[GSEC_DES_BLOCK_LEN];
  unsigned char msg[MSG_MAX];
  unsigned char out[MSG_MAX];
  size_t key_len;
  size_t msg_len = 0;
  size_t i;
  int ede3;
  int cbc;
  int decrypt;
  GSEC_Result result;
  static const char hex[] = "0123456789abcdef";

  if (argc != 6) {
    fprintf(stderr,
        "usage: des ecb|cbc|ede3|ede3-cbc encrypt|decrypt hexkey hexiv|- hexmsg\n");
    return 2;
  }
  ede3 = strcmp(argv[1], "ede3") == 0 || strcmp(argv[1], "ede3-cbc") == 0;
  cbc = strcmp(argv[1], "cbc") == 0 || strcmp(argv[1], "ede3-cbc") == 0;
  if (!ede3 && strcmp(argv[1], "ecb") != 0 && strcmp(argv[1], "cbc") != 0) {
    return 2;
  }
  decrypt = strcmp(argv[2], "decrypt") == 0;
  if (!decrypt && strcmp(argv[2], "encrypt") != 0) {
    return 2;
  }
  key_len = ede3 ? GSEC_DES_EDE3_KEY_LEN : GSEC_DES_KEY_LEN;
  if (!parse_exact(argv[3], key, key_len) ||
      !parse_exact(argv[4], iv, cbc ? GSEC_DES_BLOCK_LEN : 0) ||
      !parse_msg(argv[5], msg, &msg_len)) {
    return 2;
  }
  if (!cbc && msg_len != GSEC_DES_BLOCK_LEN) {
    return 2;
  }
  if (strcmp(argv[1], "ecb") == 0 || strcmp(argv[1], "ede3") == 0) {
    if (ede3) {
      result = decrypt ? gsec_des_ede3_decrypt(key, msg, out)
                       : gsec_des_ede3_encrypt(key, msg, out);
    } else {
      result = decrypt ? gsec_des_decrypt(key, msg, out)
                       : gsec_des_encrypt(key, msg, out);
    }
  } else if (ede3) {
    result = decrypt
        ? gsec_des_ede3_cbc_decrypt(key, iv, msg_len == 0 ? NULL : msg,
            msg_len, msg_len == 0 ? NULL : out)
        : gsec_des_ede3_cbc_encrypt(key, iv, msg_len == 0 ? NULL : msg,
            msg_len, msg_len == 0 ? NULL : out);
  } else {
    result = decrypt
        ? gsec_des_cbc_decrypt(key, iv, msg_len == 0 ? NULL : msg, msg_len,
            msg_len == 0 ? NULL : out)
        : gsec_des_cbc_encrypt(key, iv, msg_len == 0 ? NULL : msg, msg_len,
            msg_len == 0 ? NULL : out);
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
