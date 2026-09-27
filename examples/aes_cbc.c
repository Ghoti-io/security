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
 * Encrypt or decrypt with AES-CBC and no padding.
 *
 * `aes_cbc encrypt|decrypt 128|192|256 <hexkey> <hexiv> <hexmsg>`
 * The message length is a multiple of 16 bytes, or empty. Prints
 * lowercase hex and a newline. `make check-oracle` compares it with
 * OpenSSL CBC and no padding.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/aes_cbc.h>
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
  if ((len % 2u) != 0 || len / 2u > MSG_MAX || ((len / 2u) % 16u) != 0) {
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

static int bits_of(const char * text, size_t * key_len) {
  if (strcmp(text, "128") == 0) {
    *key_len = GSEC_AES128_KEY_LEN;
    return 1;
  }
  if (strcmp(text, "192") == 0) {
    *key_len = GSEC_AES192_KEY_LEN;
    return 1;
  }
  if (strcmp(text, "256") == 0) {
    *key_len = GSEC_AES256_KEY_LEN;
    return 1;
  }
  return 0;
}

int main(int argc, char ** argv) {
  unsigned char key[GSEC_AES256_KEY_LEN];
  unsigned char iv[GSEC_AES_BLOCK_LEN];
  unsigned char msg[MSG_MAX];
  unsigned char out[MSG_MAX];
  size_t key_len = 0;
  size_t msg_len = 0;
  size_t i;
  int decrypt;
  GSEC_Result result;
  static const char hex[] = "0123456789abcdef";

  if (argc != 6) {
    fprintf(stderr,
        "usage: aes_cbc encrypt|decrypt 128|192|256 hexkey hexiv hexmsg\n");
    return 2;
  }
  decrypt = strcmp(argv[1], "decrypt") == 0;
  if (!decrypt && strcmp(argv[1], "encrypt") != 0) {
    return 2;
  }
  if (!bits_of(argv[2], &key_len) || !parse_exact(argv[3], key, key_len) ||
      !parse_exact(argv[4], iv, GSEC_AES_BLOCK_LEN) ||
      !parse_msg(argv[5], msg, &msg_len)) {
    return 2;
  }
  result = decrypt
      ? gsec_aes_cbc_decrypt(key, key_len, iv, msg_len == 0 ? NULL : msg,
          msg_len, msg_len == 0 ? NULL : out)
      : gsec_aes_cbc_encrypt(key, key_len, iv, msg_len == 0 ? NULL : msg,
          msg_len, msg_len == 0 ? NULL : out);
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
