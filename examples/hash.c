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
 * `hash sha384` or `hash sha512`. `--chunk N` absorbs stdin N bytes at a
 * time. The message is capped at 1 MiB. `make check-oracle` runs both
 * forms against the pinned OpenSSL.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/sha384.h>
#include <ghoti.io/security/sha512.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MESSAGE (1u << 20)

static int print_digest(const unsigned char * digest, size_t n) {
  static const char hex[] = "0123456789abcdef";
  char text[GSEC_SHA512_DIGEST_LEN * 2u + 1u];
  size_t i;

  if (n > GSEC_SHA512_DIGEST_LEN) {
    return 1;
  }
  for (i = 0; i < n; i++) {
    text[i * 2u] = hex[digest[i] >> 4];
    text[i * 2u + 1u] = hex[digest[i] & 0x0fu];
  }
  text[n * 2u] = '\n';
  if (fwrite(text, 1, n * 2u + 1u, stdout) != n * 2u + 1u) {
    return 1;
  }
  return 0;
}

static int hash_oneshot(const char * alg) {
  unsigned char * buf;
  unsigned char digest[GSEC_SHA512_DIGEST_LEN];
  size_t n = 0;
  size_t digest_len;
  GSEC_Result result;
  int rc;

  buf = malloc(MAX_MESSAGE);
  if (buf == NULL) {
    return 2;
  }
  while (n < MAX_MESSAGE) {
    size_t got = fread(buf + n, 1, MAX_MESSAGE - n, stdin);
    n += got;
    if (got == 0) {
      break;
    }
  }
  if (ferror(stdin) || !feof(stdin)) {
    gsec_wipe(buf, MAX_MESSAGE);
    free(buf);
    return 2;
  }
  if (strcmp(alg, "sha512") == 0) {
    digest_len = GSEC_SHA512_DIGEST_LEN;
    result = gsec_sha512(n == 0 ? NULL : buf, n, digest);
  } else if (strcmp(alg, "sha384") == 0) {
    digest_len = GSEC_SHA384_DIGEST_LEN;
    result = gsec_sha384(n == 0 ? NULL : buf, n, digest);
  } else {
    gsec_wipe(buf, MAX_MESSAGE);
    free(buf);
    return 2;
  }
  gsec_wipe(buf, MAX_MESSAGE);
  free(buf);
  if (result != GSEC_OK) {
    return 1;
  }
  rc = print_digest(digest, digest_len);
  gsec_wipe(digest, sizeof digest);
  return rc;
}

static int hash_chunks(const char * alg, size_t chunk) {
  unsigned char * buf;
  unsigned char digest[GSEC_SHA512_DIGEST_LEN];
  GSEC_Sha512 sha512;
  GSEC_Sha384 sha384;
  size_t total = 0;
  size_t digest_len = 0;
  GSEC_Result result;
  int rc;
  int is_512;

  if (chunk == 0 || chunk > MAX_MESSAGE) {
    return 2;
  }
  if (strcmp(alg, "sha512") == 0) {
    is_512 = 1;
    digest_len = GSEC_SHA512_DIGEST_LEN;
    result = gsec_sha512_init(&sha512);
  } else if (strcmp(alg, "sha384") == 0) {
    is_512 = 0;
    digest_len = GSEC_SHA384_DIGEST_LEN;
    result = gsec_sha384_init(&sha384);
  } else {
    return 2;
  }
  if (result != GSEC_OK) {
    return 1;
  }
  buf = malloc(chunk);
  if (buf == NULL) {
    if (is_512) {
      gsec_wipe(&sha512, sizeof sha512);
    } else {
      gsec_wipe(&sha384, sizeof sha384);
    }
    return 2;
  }
  for (;;) {
    size_t got = fread(buf, 1, chunk, stdin);
    if (got > 0) {
      if (total > MAX_MESSAGE - got) {
        gsec_wipe(buf, chunk);
        free(buf);
        if (is_512) {
          gsec_wipe(&sha512, sizeof sha512);
        } else {
          gsec_wipe(&sha384, sizeof sha384);
        }
        return 2;
      }
      total += got;
      if (is_512) {
        result = gsec_sha512_update(&sha512, buf, got);
      } else {
        result = gsec_sha384_update(&sha384, buf, got);
      }
      gsec_wipe(buf, chunk);
      if (result != GSEC_OK) {
        free(buf);
        if (is_512) {
          gsec_wipe(&sha512, sizeof sha512);
        } else {
          gsec_wipe(&sha384, sizeof sha384);
        }
        return 1;
      }
    }
    if (got < chunk) {
      break;
    }
  }
  free(buf);
  if (ferror(stdin)) {
    if (is_512) {
      gsec_wipe(&sha512, sizeof sha512);
    } else {
      gsec_wipe(&sha384, sizeof sha384);
    }
    return 2;
  }
  if (is_512) {
    result = gsec_sha512_final(&sha512, digest);
    if (result != GSEC_OK) {
      gsec_wipe(&sha512, sizeof sha512);
      return 1;
    }
  } else {
    result = gsec_sha384_final(&sha384, digest);
    if (result != GSEC_OK) {
      gsec_wipe(&sha384, sizeof sha384);
      return 1;
    }
  }
  rc = print_digest(digest, digest_len);
  gsec_wipe(digest, sizeof digest);
  return rc;
}

int main(int argc, char ** argv) {
  if (argc == 2) {
    return hash_oneshot(argv[1]);
  }
  if (argc == 4 && strcmp(argv[2], "--chunk") == 0) {
    char * end = NULL;
    unsigned long chunk;

    errno = 0;
    chunk = strtoul(argv[3], &end, 10);
    if (errno != 0 || end == argv[3] || *end != '\0') {
      return 2;
    }
    return hash_chunks(argv[1], (size_t)chunk);
  }
  fprintf(stderr, "usage: hash sha384|sha512 [--chunk N] < message\n");
  return 2;
}
