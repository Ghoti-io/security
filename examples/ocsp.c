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
 * Read a basic OCSP response.
 *
 * `ocsp <response.der> <issuer.der> <hexserial>` prints `good`,
 * `revoked` and the revocation instant, or `unknown`, when the issuer
 * signed the response. The issuer name and key hashes are SHA-1, which
 * is what a response from that era carries. The issuer key has to be
 * P-256 or P-384. Anything else exits 1.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/hmac.h>
#include <ghoti.io/security/ocsp.h>
#include <ghoti.io/security/sha1.h>
#include <ghoti.io/security/x509.h>

#include <stdio.h>
#include <string.h>

static int nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  return -1;
}

static int read_file(const char * path, unsigned char * buf, size_t cap,
    size_t * n) {
  FILE * in = fopen(path, "rb");
  if (in == NULL) {
    return 0;
  }
  *n = fread(buf, 1, cap, in);
  if (!feof(in)) {
    fclose(in);
    return 0;
  }
  fclose(in);
  return 1;
}

static int parse_hex(const char * text, unsigned char * out, size_t cap,
    size_t * n) {
  size_t len = strlen(text);
  size_t i;

  if ((len % 2u) != 0 || len / 2u == 0 || len / 2u > cap) {
    return 0;
  }
  *n = len / 2u;
  for (i = 0; i < *n; i++) {
    int hi = nibble(text[i * 2u]);
    int lo = nibble(text[i * 2u + 1u]);
    if (hi < 0 || lo < 0) {
      return 0;
    }
    out[i] = (unsigned char)((hi << 4) | lo);
  }
  return 1;
}

int main(int argc, char ** argv) {
  unsigned char response[GSEC_X509_DER_MAX];
  unsigned char issuer[GSEC_X509_DER_MAX];
  unsigned char serial[32];
  unsigned char point[1u + 96u];
  unsigned char name_hash[GSEC_SHA1_DIGEST_LEN];
  unsigned char key_hash[GSEC_SHA1_DIGEST_LEN];
  size_t response_len = 0;
  size_t issuer_len = 0;
  size_t serial_len = 0;
  uint32_t status = 99;
  int64_t when = 0;
  GSEC_Ocsp ocsp;
  GSEC_X509 ca;

  if (argc != 4) {
    fprintf(stderr, "usage: ocsp <response.der> <issuer.der> <hexserial>\n");
    return 2;
  }
  if (!read_file(argv[1], response, sizeof response, &response_len) ||
      !read_file(argv[2], issuer, sizeof issuer, &issuer_len) ||
      !parse_hex(argv[3], serial, sizeof serial, &serial_len)) {
    return 2;
  }
  if (gsec_ocsp_parse(response, response_len, &ocsp) != GSEC_OK ||
      gsec_x509_parse(issuer, issuer_len, &ca) != GSEC_OK ||
      gsec_ocsp_signed_by(&ocsp, &ca) != GSEC_OK) {
    return 1;
  }
  if ((ca.key != GSEC_X509_P256 && ca.key != GSEC_X509_P384) ||
      ca.point_len > 96u) {
    return 1;
  }
  point[0] = 0x04;
  memcpy(point + 1, ca.point, ca.point_len);
  if (gsec_sha1(ca.subject, ca.subject_len, name_hash) != GSEC_OK ||
      gsec_sha1(point, 1u + ca.point_len, key_hash) != GSEC_OK ||
      gsec_ocsp_status(&ocsp, GSEC_HMAC_SHA1, name_hash, sizeof name_hash,
          key_hash, sizeof key_hash, serial, serial_len, &status, &when)
          != GSEC_OK) {
    return 1;
  }
  if (status == GSEC_OCSP_GOOD) {
    printf("good\n");
  } else if (status == GSEC_OCSP_REVOKED) {
    printf("revoked %lld\n", (long long)when);
  } else if (status == GSEC_OCSP_UNKNOWN) {
    printf("unknown\n");
  } else {
    return 1;
  }
  return 0;
}
