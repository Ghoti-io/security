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
 * Decode the first PEM block on stdin and write the bytes to stdout.
 *
 * The label is printed on stderr. A file that is not one block exits 1.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/pem.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PEM_MAX (1024u * 1024u)

int main(void) {
  unsigned char * text;
  unsigned char * der;
  char label[64];
  size_t n;
  size_t out_len;
  size_t cap;

  cap = PEM_MAX;
  text = (unsigned char *)malloc(cap);
  der = (unsigned char *)malloc(cap);
  if (text == NULL || der == NULL) {
    free(text);
    free(der);
    return 1;
  }
  n = fread(text, 1, cap, stdin);
  if (!feof(stdin)) {
    free(text);
    free(der);
    return 1;
  }
  memset(label, 0, sizeof label);
  if (gsec_pem_decode(text, n, der, cap, &out_len, label, sizeof label - 1u) !=
      GSEC_OK) {
    free(text);
    free(der);
    return 1;
  }
  fprintf(stderr, "%s\n", label);
  if (fwrite(der, 1, out_len, stdout) != out_len) {
    free(text);
    free(der);
    return 1;
  }
  free(text);
  free(der);
  return 0;
}
