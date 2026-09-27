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
 * Hash stdin and print the digest in hex.
 *
 * No arguments: one call, ::gsec_sha256. `--chunk N` absorbs stdin N bytes
 * at a time, which is how a streaming bug at a block boundary shows up
 * against the one-shot call. The message is capped at 1 MiB. `make
 * check-oracle` runs both forms against the pinned OpenSSL.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/sha256.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MESSAGE (1u << 20)

static int print_digest(const unsigned char * digest) {
  static const char hex[] = "0123456789abcdef";
  char text[GSEC_SHA256_DIGEST_LEN * 2u + 1u];
  size_t i;

  for (i = 0; i < GSEC_SHA256_DIGEST_LEN; i++) {
    text[i * 2u] = hex[digest[i] >> 4];
    text[i * 2u + 1u] = hex[digest[i] & 0x0fu];
  }
  text[GSEC_SHA256_DIGEST_LEN * 2u] = '\n';
  if (fwrite(text, 1, sizeof text, stdout) != sizeof text) {
    return 1;
  }
  return 0;
}

static unsigned char * read_all(size_t * n_out) {
  unsigned char * buf;
  size_t n = 0;

  buf = malloc(MAX_MESSAGE);
  if (buf == NULL) {
    return NULL;
  }
  while (n < MAX_MESSAGE) {
    size_t got = fread(buf + n, 1, MAX_MESSAGE - n, stdin);
    n += got;
    if (got == 0) {
      break;
    }
  }
  if (ferror(stdin)) {
    gsec_wipe(buf, MAX_MESSAGE);
    free(buf);
    return NULL;
  }
  if (!feof(stdin)) {
    gsec_wipe(buf, MAX_MESSAGE);
    free(buf);
    return NULL;
  }
  *n_out = n;
  return buf;
}

static int hash_oneshot(void) {
  unsigned char * msg;
  unsigned char digest[GSEC_SHA256_DIGEST_LEN];
  size_t n = 0;
  GSEC_Result result;
  int rc;

  msg = read_all(&n);
  if (msg == NULL) {
    return 2;
  }
  result = gsec_sha256(n == 0 ? NULL : msg, n, digest);
  gsec_wipe(msg, MAX_MESSAGE);
  free(msg);
  if (result != GSEC_OK) {
    return 1;
  }
  rc = print_digest(digest);
  gsec_wipe(digest, sizeof digest);
  return rc;
}

static int hash_chunks(size_t chunk) {
  GSEC_Sha256 ctx;
  unsigned char * buf;
  unsigned char digest[GSEC_SHA256_DIGEST_LEN];
  size_t total = 0;
  GSEC_Result result;
  int rc;

  if (chunk == 0 || chunk > MAX_MESSAGE) {
    return 2;
  }
  buf = malloc(chunk);
  if (buf == NULL) {
    return 2;
  }
  result = gsec_sha256_init(&ctx);
  if (result != GSEC_OK) {
    free(buf);
    return 1;
  }
  for (;;) {
    size_t got = fread(buf, 1, chunk, stdin);
    if (got > 0) {
      if (total > MAX_MESSAGE - got) {
        gsec_wipe(&ctx, sizeof ctx);
        gsec_wipe(buf, chunk);
        free(buf);
        return 2;
      }
      total += got;
      result = gsec_sha256_update(&ctx, buf, got);
      gsec_wipe(buf, chunk);
      if (result != GSEC_OK) {
        gsec_wipe(&ctx, sizeof ctx);
        free(buf);
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
  result = gsec_sha256_final(&ctx, digest);
  if (result != GSEC_OK) {
    gsec_wipe(&ctx, sizeof ctx);
    return 1;
  }
  rc = print_digest(digest);
  gsec_wipe(digest, sizeof digest);
  return rc;
}

int main(int argc, char ** argv) {
  if (argc == 1) {
    return hash_oneshot();
  }
  if (argc == 3 && strcmp(argv[1], "--chunk") == 0) {
    char * end = NULL;
    unsigned long chunk;

    errno = 0;
    chunk = strtoul(argv[2], &end, 10);
    if (errno != 0 || end == argv[2] || *end != '\0') {
      return 2;
    }
    return hash_chunks((size_t)chunk);
  }
  fprintf(stderr, "usage: sha256 [--chunk N] < message\n");
  return 2;
}
