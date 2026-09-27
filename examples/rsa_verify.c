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
 * RSA verification on the command line.
 *
 * `rsa_verify pkcs1 <hash> <hexn> <hexe> <hexmsg|-> <hexsig>` and
 * `rsa_verify pss <hash> <mgf> <salt> <hexn> <hexe> <hexmsg|-> <hexsig>`
 * exit 0 when the signature is accepted. hash and mgf are md5, sha1,
 * sha256, sha384, or sha512. A modulus or signature past 520 bytes, and
 * a message past 1 MiB, exit 1 and print nothing. Bad hex exits 2.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/rsa.h>
#include <ghoti.io/security/secret.h>

#include <stdio.h>
#include <stdlib.h>
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

/* 0 is success, 1 is past the cap, 2 is bad hex. */
static int parse_hex(const char * text, unsigned char * out, size_t cap,
    size_t * n) {
  size_t len;
  size_t i;

  len = strlen(text);
  if ((len % 2u) != 0) {
    return 2;
  }
  if (len / 2u > cap) {
    return 1;
  }
  *n = len / 2u;
  for (i = 0; i < *n; i++) {
    int hi = hex_nibble(text[i * 2u]);
    int lo = hex_nibble(text[i * 2u + 1u]);
    if (hi < 0 || lo < 0) {
      return 2;
    }
    out[i] = (unsigned char)((hi << 4) | lo);
  }
  return 0;
}

static int parse_message(const char * text, unsigned char ** out, size_t * n) {
  size_t len;
  size_t i;
  unsigned char * buf;

  if (text == NULL || strcmp(text, "-") == 0) {
    *out = NULL;
    *n = 0;
    return 0;
  }
  len = strlen(text);
  if ((len % 2u) != 0) {
    return 2;
  }
  if (len / 2u > (1u << 20)) {
    return 1;
  }
  *n = len / 2u;
  if (*n == 0) {
    *out = NULL;
    return 0;
  }
  buf = malloc(*n);
  if (buf == NULL) {
    return 1;
  }
  for (i = 0; i < *n; i++) {
    int hi = hex_nibble(text[i * 2u]);
    int lo = hex_nibble(text[i * 2u + 1u]);
    if (hi < 0 || lo < 0) {
      free(buf);
      return 2;
    }
    buf[i] = (unsigned char)((hi << 4) | lo);
  }
  *out = buf;
  return 0;
}

static int hash_id(const char * name, uint32_t * id) {
  if (strcmp(name, "md5") == 0) {
    *id = GSEC_RSA_MD5;
  } else if (strcmp(name, "sha1") == 0) {
    *id = GSEC_RSA_SHA1;
  } else if (strcmp(name, "sha256") == 0) {
    *id = GSEC_RSA_SHA256;
  } else if (strcmp(name, "sha384") == 0) {
    *id = GSEC_RSA_SHA384;
  } else if (strcmp(name, "sha512") == 0) {
    *id = GSEC_RSA_SHA512;
  } else {
    return 0;
  }
  return 1;
}

int main(int argc, char ** argv) {
  unsigned char nbuf[520];
  unsigned char ebuf[520];
  unsigned char sbuf[520];
  unsigned char * message = NULL;
  size_t nn = 0;
  size_t en = 0;
  size_t sn = 0;
  size_t mn = 0;
  uint32_t hash = 0;
  uint32_t mgf = 0;
  unsigned long salt = 0;
  int rc;
  int pss;
  GSEC_Result result;
  char * end = NULL;

  if (argc < 2) {
    fprintf(stderr,
        "usage: rsa_verify pkcs1 hash hexn hexe hexmsg|- hexsig | rsa_verify pss hash mgf salt hexn hexe hexmsg|- hexsig\n");
    return 2;
  }
  pss = strcmp(argv[1], "pss") == 0;
  if (!pss && strcmp(argv[1], "pkcs1") != 0) {
    fprintf(stderr,
        "usage: rsa_verify pkcs1 hash hexn hexe hexmsg|- hexsig | rsa_verify pss hash mgf salt hexn hexe hexmsg|- hexsig\n");
    return 2;
  }
  if (pss) {
    if (argc != 9 || !hash_id(argv[2], &hash) || !hash_id(argv[3], &mgf)) {
      return 2;
    }
    salt = strtoul(argv[4], &end, 10);
    if (end == argv[4] || *end != '\0') {
      return 2;
    }
    rc = parse_hex(argv[5], nbuf, sizeof nbuf, &nn);
    if (rc != 0) {
      return rc;
    }
    rc = parse_hex(argv[6], ebuf, sizeof ebuf, &en);
    if (rc != 0) {
      return rc;
    }
    rc = parse_message(argv[7], &message, &mn);
    if (rc != 0) {
      return rc;
    }
    rc = parse_hex(argv[8], sbuf, sizeof sbuf, &sn);
    if (rc != 0) {
      gsec_wipe(message, mn);
      free(message);
      return rc;
    }
    result = gsec_rsa_pss_verify(hash, mgf, nbuf, nn, ebuf, en, message, mn,
        sbuf, sn, (size_t)salt);
  } else {
    if (argc != 7 || !hash_id(argv[2], &hash)) {
      return 2;
    }
    rc = parse_hex(argv[3], nbuf, sizeof nbuf, &nn);
    if (rc != 0) {
      return rc;
    }
    rc = parse_hex(argv[4], ebuf, sizeof ebuf, &en);
    if (rc != 0) {
      return rc;
    }
    rc = parse_message(argv[5], &message, &mn);
    if (rc != 0) {
      return rc;
    }
    rc = parse_hex(argv[6], sbuf, sizeof sbuf, &sn);
    if (rc != 0) {
      gsec_wipe(message, mn);
      free(message);
      return rc;
    }
    result = gsec_rsa_pkcs1_v15_verify(hash, nbuf, nn, ebuf, en, message, mn,
        sbuf, sn);
  }
  gsec_wipe(nbuf, sizeof nbuf);
  gsec_wipe(ebuf, sizeof ebuf);
  gsec_wipe(sbuf, sizeof sbuf);
  gsec_wipe(message, mn);
  free(message);
  return result == GSEC_OK ? 0 : 1;
}
