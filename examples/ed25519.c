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
 * Ed25519 on the command line.
 *
 * `ed25519 public <hexseed>` prints the public key. `ed25519 sign
 * <hexseed> [hexmsg|-]` prints the signature. `ed25519 verify <hexpk>
 * <hexsig> [hexmsg|-]` exits 0 when the signature is accepted.
 * `verify-ctx` and `verify-ph` take the context hex before the message.
 * An empty context is `-`. A seed or
 * public key that is not 32 bytes, or a signature that is not 64, exits 1
 * and prints nothing. A message longer than 1 MiB does the same. Bad hex
 * exits 2.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/ed25519.h>
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

static int parse_hex(const char * text, unsigned char * out, size_t cap,
    size_t * n) {
  size_t len;
  size_t i;

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

/* 0 is success, 1 is a length past the cap, 2 is bad hex. `-` is empty. */
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
  unsigned char key[GSEC_ED25519_LEN];
  unsigned char sig[GSEC_ED25519_SIG_LEN];
  unsigned char * message = NULL;
  size_t n = 0;
  size_t mn = 0;
  int message_rc;
  GSEC_Result result;
  const char * command;

  if (argc < 2) {
    fprintf(stderr, "usage: ed25519 public hexseed | ed25519 sign hexseed [hexmsg|-] | ed25519 verify hexpk hexsig [hexmsg|-] | ed25519 verify-ctx|verify-ph hexpk hexsig hexctx|- [hexmsg|-]\n");
    return 2;
  }
  command = argv[1];
  if (strcmp(command, "public") == 0) {
    if (argc != 3 || !parse_hex(argv[2], key, sizeof key, &n)) {
      return 2;
    }
    if (n != GSEC_ED25519_LEN) {
      gsec_wipe(key, sizeof key);
      return 1;
    }
    result = gsec_ed25519_public(key, sig);
    gsec_wipe(key, sizeof key);
    if (result != GSEC_OK || !write_hex(sig, GSEC_ED25519_LEN)) {
      gsec_wipe(sig, sizeof sig);
      return 1;
    }
    gsec_wipe(sig, sizeof sig);
    return 0;
  }
  if (strcmp(command, "sign") == 0) {
    if (argc != 3 && argc != 4) {
      return 2;
    }
    if (!parse_hex(argv[2], key, sizeof key, &n)) {
      return 2;
    }
    if (n != GSEC_ED25519_LEN) {
      gsec_wipe(key, sizeof key);
      return 1;
    }
    message_rc = parse_message(argc == 4 ? argv[3] : NULL, &message, &mn);
    if (message_rc != 0) {
      gsec_wipe(key, sizeof key);
      return message_rc;
    }
    result = gsec_ed25519_sign(key, message, mn, sig);
    gsec_wipe(key, sizeof key);
    gsec_wipe(message, mn);
    free(message);
    if (result != GSEC_OK || !write_hex(sig, sizeof sig)) {
      gsec_wipe(sig, sizeof sig);
      return 1;
    }
    gsec_wipe(sig, sizeof sig);
    return 0;
  }
  if (strcmp(command, "verify") == 0) {
    if (argc != 4 && argc != 5) {
      return 2;
    }
    if (!parse_hex(argv[2], key, sizeof key, &n)) {
      return 2;
    }
    if (n != GSEC_ED25519_LEN) {
      gsec_wipe(key, sizeof key);
      return 1;
    }
    if (!parse_hex(argv[3], sig, sizeof sig, &n)) {
      gsec_wipe(key, sizeof key);
      return 2;
    }
    if (n != GSEC_ED25519_SIG_LEN) {
      gsec_wipe(key, sizeof key);
      gsec_wipe(sig, sizeof sig);
      return 1;
    }
    message_rc = parse_message(argc == 5 ? argv[4] : NULL, &message, &mn);
    if (message_rc != 0) {
      gsec_wipe(key, sizeof key);
      gsec_wipe(sig, sizeof sig);
      return message_rc;
    }
    result = gsec_ed25519_verify(key, message, mn, sig);
    gsec_wipe(key, sizeof key);
    gsec_wipe(sig, sizeof sig);
    gsec_wipe(message, mn);
    free(message);
    return result == GSEC_OK ? 0 : 1;
  }
  if (strcmp(command, "verify-ctx") == 0 || strcmp(command, "verify-ph") == 0) {
    unsigned char context[255];
    size_t cn = 0;
    int prehash = strcmp(command, "verify-ph") == 0;

    if (argc != 5 && argc != 6) {
      return 2;
    }
    if (!parse_hex(argv[2], key, sizeof key, &n)) {
      return 2;
    }
    if (n != GSEC_ED25519_LEN) {
      gsec_wipe(key, sizeof key);
      return 1;
    }
    if (!parse_hex(argv[3], sig, sizeof sig, &n)) {
      gsec_wipe(key, sizeof key);
      return 2;
    }
    if (n != GSEC_ED25519_SIG_LEN) {
      gsec_wipe(key, sizeof key);
      gsec_wipe(sig, sizeof sig);
      return 1;
    }
    if (strcmp(argv[4], "-") != 0) {
      if (!parse_hex(argv[4], context, sizeof context, &cn)) {
        gsec_wipe(key, sizeof key);
        gsec_wipe(sig, sizeof sig);
        return 2;
      }
    }
    message_rc = parse_message(argc == 6 ? argv[5] : NULL, &message, &mn);
    if (message_rc != 0) {
      gsec_wipe(key, sizeof key);
      gsec_wipe(sig, sizeof sig);
      gsec_wipe(context, sizeof context);
      return message_rc;
    }
    result = prehash
        ? gsec_ed25519_ph_verify(key, message, mn, sig,
            cn == 0 ? NULL : context, cn)
        : gsec_ed25519_ctx_verify(key, message, mn, sig,
            cn == 0 ? NULL : context, cn);
    gsec_wipe(key, sizeof key);
    gsec_wipe(sig, sizeof sig);
    gsec_wipe(context, sizeof context);
    gsec_wipe(message, mn);
    free(message);
    return result == GSEC_OK ? 0 : 1;
  }
  fprintf(stderr, "usage: ed25519 public hexseed | ed25519 sign hexseed [hexmsg|-] | ed25519 verify hexpk hexsig [hexmsg|-] | ed25519 verify-ctx|verify-ph hexpk hexsig hexctx|- [hexmsg|-]\n");
  return 2;
}
