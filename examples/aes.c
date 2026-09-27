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
 * Encrypt or decrypt one AES block.
 *
 * `aes encrypt 128|192|256 <hexkey> <hexblock>` and the same with
 * `decrypt`. The bit length has to match the key. Prints lowercase hex
 * and a newline. `make check-oracle` compares it with OpenSSL ECB and
 * no padding, which is one block and nothing else.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/aes.h>
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
  unsigned char block[GSEC_AES_BLOCK_LEN];
  unsigned char out[GSEC_AES_BLOCK_LEN];
  size_t key_len = 0;
  size_t i;
  int decrypt;
  GSEC_Result result;
  static const char hex[] = "0123456789abcdef";
  char text[GSEC_AES_BLOCK_LEN * 2u + 2u];

  if (argc != 5) {
    fprintf(stderr, "usage: aes encrypt|decrypt 128|192|256 hexkey hexblock\n");
    return 2;
  }
  decrypt = strcmp(argv[1], "decrypt") == 0;
  if (!decrypt && strcmp(argv[1], "encrypt") != 0) {
    return 2;
  }
  if (!bits_of(argv[2], &key_len) || !parse_exact(argv[3], key, key_len) ||
      !parse_exact(argv[4], block, GSEC_AES_BLOCK_LEN)) {
    return 2;
  }
  result = decrypt ? gsec_aes_decrypt(key, key_len, block, out)
                   : gsec_aes_encrypt(key, key_len, block, out);
  gsec_wipe(key, sizeof key);
  gsec_wipe(block, sizeof block);
  if (result != GSEC_OK) {
    gsec_wipe(out, sizeof out);
    return 1;
  }
  for (i = 0; i < GSEC_AES_BLOCK_LEN; i++) {
    text[i * 2u] = hex[out[i] >> 4];
    text[i * 2u + 1u] = hex[out[i] & 0x0fu];
  }
  text[GSEC_AES_BLOCK_LEN * 2u] = '\n';
  gsec_wipe(out, sizeof out);
  if (fwrite(text, 1, GSEC_AES_BLOCK_LEN * 2u + 1u, stdout) !=
      GSEC_AES_BLOCK_LEN * 2u + 1u) {
    return 1;
  }
  return 0;
}
