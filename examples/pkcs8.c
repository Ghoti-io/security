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
 * Read an unencrypted PKCS#8 file and print the key kind.
 *
 * The key bytes are not printed. A password-encrypted key exits 1.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/pkcs8.h>
#include <ghoti.io/security/secret.h>

#include <stdio.h>
#include <stdlib.h>

#define KEY_MAX 8192u

int main(int argc, char ** argv) {
  FILE * in;
  unsigned char buf[KEY_MAX];
  size_t n;
  GSEC_Pkcs8 key;
  const char * name;

  if (argc != 2) {
    fprintf(stderr, "usage: pkcs8 <file>\n");
    return 2;
  }
  in = fopen(argv[1], "rb");
  if (in == NULL) {
    return 2;
  }
  n = fread(buf, 1, sizeof buf, in);
  if (!feof(in)) {
    fclose(in);
    return 1;
  }
  fclose(in);
  if (gsec_pkcs8_parse(buf, n, &key) != GSEC_OK) {
    gsec_wipe(buf, sizeof buf);
    return 1;
  }
  gsec_wipe(buf, sizeof buf);
  if (key.kind == GSEC_PKCS8_RSA) {
    name = "rsa";
  } else if (key.kind == GSEC_PKCS8_P256) {
    name = "p256";
  } else if (key.kind == GSEC_PKCS8_P384) {
    name = "p384";
  } else if (key.kind == GSEC_PKCS8_ED25519) {
    name = "ed25519";
  } else {
    return 1;
  }
  printf("%s\n", name);
  return 0;
}
