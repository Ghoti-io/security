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
 * MAC stdin and print the MAC in hex.
 *
 * `hmac sha256 <hexkey>`. `--chunk N` absorbs stdin N bytes at a time.
 * The message is capped at 1 MiB. `make check-oracle` runs both forms
 * against the pinned OpenSSL.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/hmac.h>
#include <ghoti.io/security/secret.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MESSAGE (1u << 20)
#define MAX_KEY 256

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

static int parse_key(const char * text, unsigned char * out, size_t * n_out) {
  size_t len = strlen(text);
  size_t i;

  if (len % 2 != 0 || len / 2 > MAX_KEY) {
    return 0;
  }
  for (i = 0; i < len; i += 2) {
    int hi = hex_nibble(text[i]);
    int lo = hex_nibble(text[i + 1]);
    if (hi < 0 || lo < 0) {
      return 0;
    }
    out[i / 2] = (unsigned char)((hi << 4) | lo);
  }
  *n_out = len / 2;
  return 1;
}

static uint32_t hash_id(const char * name, size_t * digest_len) {
  if (strcmp(name, "sha1") == 0) {
    *digest_len = GSEC_SHA1_DIGEST_LEN;
    return GSEC_HMAC_SHA1;
  }
  if (strcmp(name, "sha256") == 0) {
    *digest_len = GSEC_SHA256_DIGEST_LEN;
    return GSEC_HMAC_SHA256;
  }
  if (strcmp(name, "sha384") == 0) {
    *digest_len = GSEC_SHA384_DIGEST_LEN;
    return GSEC_HMAC_SHA384;
  }
  if (strcmp(name, "sha512") == 0) {
    *digest_len = GSEC_SHA512_DIGEST_LEN;
    return GSEC_HMAC_SHA512;
  }
  return 0;
}

static int print_mac(const unsigned char * mac, size_t n) {
  static const char hex[] = "0123456789abcdef";
  char text[GSEC_SHA512_DIGEST_LEN * 2u + 1u];
  size_t i;

  for (i = 0; i < n; i++) {
    text[i * 2u] = hex[mac[i] >> 4];
    text[i * 2u + 1u] = hex[mac[i] & 0x0fu];
  }
  text[n * 2u] = '\n';
  if (fwrite(text, 1, n * 2u + 1u, stdout) != n * 2u + 1u) {
    return 1;
  }
  return 0;
}

static int run(uint32_t hash, size_t digest_len, const unsigned char * key,
    size_t key_len, size_t chunk) {
  unsigned char * buf;
  unsigned char mac[GSEC_SHA512_DIGEST_LEN];
  GSEC_Hmac ctx;
  size_t total = 0;
  GSEC_Result result;
  int rc;

  if (chunk == 0) {
    buf = malloc(MAX_MESSAGE);
    if (buf == NULL) {
      return 2;
    }
    total = 0;
    while (total < MAX_MESSAGE) {
      size_t got = fread(buf + total, 1, MAX_MESSAGE - total, stdin);
      total += got;
      if (got == 0) {
        break;
      }
    }
    if (ferror(stdin) || !feof(stdin)) {
      gsec_wipe(buf, MAX_MESSAGE);
      free(buf);
      return 2;
    }
    result = gsec_hmac(hash, key_len == 0 ? NULL : key, key_len,
        total == 0 ? NULL : buf, total, mac);
    gsec_wipe(buf, MAX_MESSAGE);
    free(buf);
  } else {
    if (chunk > MAX_MESSAGE) {
      return 2;
    }
    result = gsec_hmac_init(&ctx, hash, key_len == 0 ? NULL : key, key_len);
    if (result != GSEC_OK) {
      return 1;
    }
    buf = malloc(chunk);
    if (buf == NULL) {
      gsec_wipe(&ctx, sizeof ctx);
      return 2;
    }
    for (;;) {
      size_t got = fread(buf, 1, chunk, stdin);
      if (got > 0) {
        if (total > MAX_MESSAGE - got) {
          gsec_wipe(buf, chunk);
          free(buf);
          gsec_wipe(&ctx, sizeof ctx);
          return 2;
        }
        total += got;
        result = gsec_hmac_update(&ctx, buf, got);
        gsec_wipe(buf, chunk);
        if (result != GSEC_OK) {
          free(buf);
          gsec_wipe(&ctx, sizeof ctx);
          return 1;
        }
      }
      if (got < chunk) {
        break;
      }
    }
    free(buf);
    if (ferror(stdin)) {
      gsec_wipe(&ctx, sizeof ctx);
      return 2;
    }
    result = gsec_hmac_final(&ctx, mac);
    if (result != GSEC_OK) {
      gsec_wipe(&ctx, sizeof ctx);
      return 1;
    }
  }
  if (result != GSEC_OK) {
    return 1;
  }
  rc = print_mac(mac, digest_len);
  gsec_wipe(mac, sizeof mac);
  return rc;
}

int main(int argc, char ** argv) {
  unsigned char key[MAX_KEY];
  size_t key_len = 0;
  size_t digest_len = 0;
  uint32_t hash;
  size_t chunk = 0;

  if (argc != 3 && argc != 5) {
    fprintf(stderr, "usage: hmac sha1|sha256|sha384|sha512 hexkey [--chunk N]\n");
    return 2;
  }
  hash = hash_id(argv[1], &digest_len);
  if (hash == 0 || !parse_key(argv[2], key, &key_len)) {
    return 2;
  }
  if (argc == 5) {
    char * end = NULL;
    unsigned long value;

    if (strcmp(argv[3], "--chunk") != 0) {
      gsec_wipe(key, sizeof key);
      return 2;
    }
    errno = 0;
    value = strtoul(argv[4], &end, 10);
    if (errno != 0 || end == argv[4] || *end != '\0' || value == 0) {
      gsec_wipe(key, sizeof key);
      return 2;
    }
    chunk = (size_t)value;
  }
  {
    int rc = run(hash, digest_len, key, key_len, chunk);
    gsec_wipe(key, sizeof key);
    return rc;
  }
}
