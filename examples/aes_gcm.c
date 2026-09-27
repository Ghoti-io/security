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
 * AES-GCM over stdin.
 *
 * `aes-gcm encrypt 128|192|256 <hexkey> <hexiv> <hextag aad or ->` reads
 * the plaintext and prints the ciphertext hex, a newline, the 16-byte tag
 * hex, and a newline. `decrypt` takes the tag hex as a sixth argument and
 * prints the plaintext hex. A rejected tag exits 1 and prints nothing.
 * The message is capped at 1 MiB. The nonce and the additional data are
 * capped at 4 KiB.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/aes_gcm.h>
#include <ghoti.io/security/secret.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MESSAGE (1u << 20)
#define MAX_AUX 4096u

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
  unsigned char key[GSEC_AES256_KEY_LEN];
  unsigned char iv[MAX_AUX];
  unsigned char aad[MAX_AUX];
  unsigned char tag[16];
  unsigned char * in;
  unsigned char * out;
  size_t key_len = 0;
  size_t iv_len = 0;
  size_t aad_len = 0;
  size_t tag_len = 16;
  size_t n = 0;
  int encrypt;
  GSEC_Result result;

  if (argc != 6 && argc != 7) {
    fprintf(stderr,
        "usage: aes-gcm encrypt|decrypt 128|192|256 hexkey hexiv hextag-or-aad\n");
    return 2;
  }
  if (strcmp(argv[1], "encrypt") == 0) {
    encrypt = 1;
    if (argc != 6) {
      return 2;
    }
  } else if (strcmp(argv[1], "decrypt") == 0) {
    encrypt = 0;
    if (argc != 7) {
      return 2;
    }
  } else {
    return 2;
  }
  if (strcmp(argv[2], "128") == 0) {
    key_len = GSEC_AES128_KEY_LEN;
  } else if (strcmp(argv[2], "192") == 0) {
    key_len = GSEC_AES192_KEY_LEN;
  } else if (strcmp(argv[2], "256") == 0) {
    key_len = GSEC_AES256_KEY_LEN;
  } else {
    return 2;
  }
  if (!parse_hex(argv[3], key, key_len, &key_len) ||
      key_len != (strcmp(argv[2], "128") == 0 ? 16u :
          strcmp(argv[2], "192") == 0 ? 24u : 32u)) {
    return 2;
  }
  if (!parse_hex(argv[4], iv, MAX_AUX, &iv_len) ||
      !parse_hex(argv[5], aad, MAX_AUX, &aad_len)) {
    return 2;
  }
  if (!encrypt && !parse_hex(argv[6], tag, sizeof tag, &tag_len)) {
    return 2;
  }
  in = malloc(MAX_MESSAGE);
  out = malloc(MAX_MESSAGE);
  if (in == NULL || out == NULL) {
    free(in);
    free(out);
    return 2;
  }
  while (n < MAX_MESSAGE) {
    size_t got = fread(in + n, 1, MAX_MESSAGE - n, stdin);
    n += got;
    if (got == 0) {
      break;
    }
  }
  if (ferror(stdin) || !feof(stdin)) {
    gsec_wipe(in, MAX_MESSAGE);
    free(in);
    free(out);
    return 2;
  }
  if (encrypt) {
    result = gsec_aes_gcm_encrypt(key, key_len, iv_len == 0 ? NULL : iv, iv_len,
        aad_len == 0 ? NULL : aad, aad_len, n == 0 ? NULL : in, n,
        n == 0 ? NULL : out, tag, sizeof tag);
  } else {
    result = gsec_aes_gcm_decrypt(key, key_len, iv_len == 0 ? NULL : iv, iv_len,
        aad_len == 0 ? NULL : aad, aad_len, n == 0 ? NULL : in, n,
        n == 0 ? NULL : out, tag, tag_len);
  }
  gsec_wipe(key, sizeof key);
  gsec_wipe(iv, sizeof iv);
  gsec_wipe(aad, sizeof aad);
  gsec_wipe(in, MAX_MESSAGE);
  free(in);
  if (result != GSEC_OK) {
    gsec_wipe(out, MAX_MESSAGE);
    gsec_wipe(tag, sizeof tag);
    free(out);
    return 1;
  }
  if (!write_hex(out, n) || (encrypt && !write_hex(tag, sizeof tag))) {
    gsec_wipe(out, MAX_MESSAGE);
    gsec_wipe(tag, sizeof tag);
    free(out);
    return 1;
  }
  gsec_wipe(out, MAX_MESSAGE);
  gsec_wipe(tag, sizeof tag);
  free(out);
  return 0;
}
