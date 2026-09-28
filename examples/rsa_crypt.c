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
 * RSA decryption on the command line.
 *
 * `rsa_crypt decrypt-pkcs1 <hexn> <hexe> <hexd> <hexcipher>` and
 * `rsa_crypt decrypt-oaep <hash> <mgf> <hexn> <hexe> <hexd> <hexlabel|->
 * <hexcipher>` print the message as lowercase hex. hash and mgf are
 * md5, sha1, sha256, sha384, or sha512. hash is the label hash. mgf is
 * MGF1. A bad ciphertext exits 1 and prints nothing. Bad hex exits 2.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/rsa.h>
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

static int parse_hex(const char * text, unsigned char * out, size_t cap,
    size_t * n) {
  size_t len;
  size_t i;

  if (strcmp(text, "-") == 0) {
    *n = 0;
    return 0;
  }
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

static void print_hex(const unsigned char * p, size_t n) {
  size_t i;

  for (i = 0; i < n; i++) {
    printf("%02x", p[i]);
  }
  printf("\n");
}

int main(int argc, char ** argv) {
  unsigned char nbuf[520];
  unsigned char ebuf[520];
  unsigned char dbuf[520];
  unsigned char cbuf[520];
  unsigned char lbuf[4096];
  unsigned char mbuf[512];
  size_t nn = 0;
  size_t en = 0;
  size_t dn = 0;
  size_t cn = 0;
  size_t ln = 0;
  size_t mn = 0;
  uint32_t hash = 0;
  uint32_t mgf = 0;
  int oaep;
  int rc;
  GSEC_Result result;

  if (argc < 2) {
    fprintf(stderr,
        "usage: rsa_crypt decrypt-pkcs1 ... | rsa_crypt decrypt-oaep ...\n");
    return 2;
  }
  oaep = strcmp(argv[1], "decrypt-oaep") == 0;
  if (!oaep && strcmp(argv[1], "decrypt-pkcs1") != 0) {
    return 2;
  }
  if (oaep) {
    if (argc != 9 || !hash_id(argv[2], &hash) || !hash_id(argv[3], &mgf)) {
      return 2;
    }
    rc = parse_hex(argv[4], nbuf, sizeof nbuf, &nn);
    if (rc != 0) {
      return rc;
    }
    rc = parse_hex(argv[5], ebuf, sizeof ebuf, &en);
    if (rc != 0) {
      return rc;
    }
    rc = parse_hex(argv[6], dbuf, sizeof dbuf, &dn);
    if (rc != 0) {
      return rc;
    }
    rc = parse_hex(argv[7], lbuf, sizeof lbuf, &ln);
    if (rc != 0) {
      return rc;
    }
    rc = parse_hex(argv[8], cbuf, sizeof cbuf, &cn);
    if (rc != 0) {
      return rc;
    }
    result = gsec_rsa_oaep_mgf_decrypt(hash, mgf, nbuf, nn, ebuf, en, dbuf, dn,
        ln == 0 ? NULL : lbuf, ln, cbuf, cn, mbuf, sizeof mbuf, &mn);
  } else {
    if (argc != 6) {
      return 2;
    }
    rc = parse_hex(argv[2], nbuf, sizeof nbuf, &nn);
    if (rc != 0) {
      return rc;
    }
    rc = parse_hex(argv[3], ebuf, sizeof ebuf, &en);
    if (rc != 0) {
      return rc;
    }
    rc = parse_hex(argv[4], dbuf, sizeof dbuf, &dn);
    if (rc != 0) {
      return rc;
    }
    rc = parse_hex(argv[5], cbuf, sizeof cbuf, &cn);
    if (rc != 0) {
      return rc;
    }
    result = gsec_rsa_pkcs1_v15_decrypt(nbuf, nn, ebuf, en, dbuf, dn, cbuf, cn,
        mbuf, sizeof mbuf, &mn);
  }
  gsec_wipe(nbuf, sizeof nbuf);
  gsec_wipe(ebuf, sizeof ebuf);
  gsec_wipe(dbuf, sizeof dbuf);
  gsec_wipe(cbuf, sizeof cbuf);
  gsec_wipe(lbuf, sizeof lbuf);
  if (result != GSEC_OK) {
    gsec_wipe(mbuf, sizeof mbuf);
    return 1;
  }
  print_hex(mbuf, mn);
  gsec_wipe(mbuf, sizeof mbuf);
  return 0;
}
