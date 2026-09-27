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
 * AES-CTR over stdin.
 *
 * `aes-ctr 128|192|256 be|le <hexkey> <hexcounter>`. The message is capped
 * at 1 MiB. Prints lowercase hex and a newline.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/aes_ctr.h>
#include <ghoti.io/security/secret.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MESSAGE (1u << 20)

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

int main(int argc, char ** argv) {
  unsigned char key[GSEC_AES256_KEY_LEN];
  unsigned char counter[GSEC_AES_BLOCK_LEN];
  unsigned char * buf;
  unsigned char * out;
  size_t key_len = 0;
  size_t n = 0;
  uint32_t direction;
  size_t i;
  GSEC_Result result;
  static const char hex[] = "0123456789abcdef";

  if (argc != 5) {
    fprintf(stderr, "usage: aes-ctr 128|192|256 be|le hexkey hexcounter\n");
    return 2;
  }
  if (strcmp(argv[1], "128") == 0) {
    key_len = GSEC_AES128_KEY_LEN;
  } else if (strcmp(argv[1], "192") == 0) {
    key_len = GSEC_AES192_KEY_LEN;
  } else if (strcmp(argv[1], "256") == 0) {
    key_len = GSEC_AES256_KEY_LEN;
  } else {
    return 2;
  }
  if (strcmp(argv[2], "be") == 0) {
    direction = GSEC_AES_CTR_BE;
  } else if (strcmp(argv[2], "le") == 0) {
    direction = GSEC_AES_CTR_LE;
  } else {
    return 2;
  }
  if (!parse_exact(argv[3], key, key_len) ||
      !parse_exact(argv[4], counter, GSEC_AES_BLOCK_LEN)) {
    return 2;
  }
  buf = malloc(MAX_MESSAGE);
  out = malloc(MAX_MESSAGE);
  if (buf == NULL || out == NULL) {
    free(buf);
    free(out);
    return 2;
  }
  while (n < MAX_MESSAGE) {
    size_t got = fread(buf + n, 1, MAX_MESSAGE - n, stdin);
    n += got;
    if (got == 0) {
      break;
    }
  }
  if (ferror(stdin) || !feof(stdin)) {
    gsec_wipe(buf, MAX_MESSAGE);
    free(buf);
    free(out);
    return 2;
  }
  result = gsec_aes_ctr(key, key_len, counter, direction, n == 0 ? NULL : buf, out, n);
  gsec_wipe(key, sizeof key);
  gsec_wipe(counter, sizeof counter);
  gsec_wipe(buf, MAX_MESSAGE);
  free(buf);
  if (result != GSEC_OK) {
    gsec_wipe(out, MAX_MESSAGE);
    free(out);
    return 1;
  }
  for (i = 0; i < n; i++) {
    char pair[2];
    pair[0] = hex[out[i] >> 4];
    pair[1] = hex[out[i] & 0x0fu];
    if (fwrite(pair, 1, 2, stdout) != 2) {
      gsec_wipe(out, MAX_MESSAGE);
      free(out);
      return 1;
    }
  }
  gsec_wipe(out, MAX_MESSAGE);
  free(out);
  if (fputc('\n', stdout) == EOF) {
    return 1;
  }
  return 0;
}
