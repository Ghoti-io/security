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
 * Print whether two hex strings compare equal.
 *
 * The bytes are the caller's, passed on the command line. The program prints
 * a status word and not the bytes.
 */

#include <ghoti.io/security/macros.h>

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

static int decode(const char * text, unsigned char ** out, size_t * n) {
  size_t len = strlen(text);
  size_t i;

  if (len % 2 != 0) {
    return -1;
  }
  *n = len / 2;
  *out = (unsigned char *)malloc(*n == 0 ? 1 : *n);
  if (*out == NULL) {
    return -1;
  }
  for (i = 0; i < *n; i++) {
    int hi = hex_nibble(text[2 * i]);
    int lo = hex_nibble(text[2 * i + 1]);

    if (hi < 0 || lo < 0) {
      free(*out);
      *out = NULL;
      return -1;
    }
    (*out)[i] = (unsigned char)((hi << 4) | lo);
  }
  return 0;
}

int main(int argc, char ** argv) {
  unsigned char * a = NULL;
  unsigned char * b = NULL;
  size_t na = 0;
  size_t nb = 0;
  GSEC_Result result;

  if (argc != 3) {
    fprintf(stderr, "usage: equal <hex> <hex>\n");
    return 2;
  }
  if (decode(argv[1], &a, &na) != 0 || decode(argv[2], &b, &nb) != 0
      || na != nb) {
    fprintf(stderr, "invalid hex, or the two strings differ in length\n");
    free(a);
    free(b);
    return 2;
  }
  result = gsec_equal(a, b, na);
  gsec_wipe(a, na);
  gsec_wipe(b, nb);
  free(a);
  free(b);
  if (result == GSEC_OK) {
    printf("equal\n");
    return 0;
  }
  if (result == GSEC_ERR_MISMATCH) {
    printf("mismatch\n");
    return 1;
  }
  printf("%s\n", gsec_result_string(result));
  return 2;
}
