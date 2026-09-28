/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * RC4 through OpenSSL's EVP, with the key length the caller gave.
 *
 * `openssl enc -rc4` zero-pads a short `-K`. This program does not.
 * `rc4-evp <hexkey> <hexmsg>` prints lowercase hex ciphertext.
 */

#include <openssl/evp.h>
#include <openssl/provider.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int nibble(char c) {
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

static int parse(const char * text, unsigned char ** out, size_t * n) {
  size_t len;
  size_t i;

  len = strlen(text);
  if ((len % 2u) != 0 || len / 2u > 4096) {
    return 0;
  }
  *n = len / 2u;
  *out = malloc(*n == 0 ? 1 : *n);
  if (*out == NULL) {
    return 0;
  }
  for (i = 0; i < *n; i++) {
    int hi = nibble(text[i * 2u]);
    int lo = nibble(text[i * 2u + 1u]);

    if (hi < 0 || lo < 0) {
      return 0;
    }
    (*out)[i] = (unsigned char)((hi << 4) | lo);
  }
  return 1;
}

int main(int argc, char ** argv) {
  unsigned char * key = NULL;
  unsigned char * msg = NULL;
  unsigned char * out = NULL;
  size_t key_len = 0;
  size_t msg_len = 0;
  EVP_CIPHER_CTX * ctx;
  EVP_CIPHER * cipher;
  int produced = 0;
  int final_len = 0;
  size_t i;

  if (argc != 3) {
    return 2;
  }
  if (!parse(argv[1], &key, &key_len) || key_len < 1 || key_len > 256) {
    return 2;
  }
  if (!parse(argv[2], &msg, &msg_len)) {
    return 2;
  }
  if (OSSL_PROVIDER_load(NULL, "legacy") == NULL ||
      OSSL_PROVIDER_load(NULL, "default") == NULL) {
    return 1;
  }
  cipher = EVP_CIPHER_fetch(NULL, "RC4", NULL);
  ctx = EVP_CIPHER_CTX_new();
  out = malloc(msg_len + 16);
  if (cipher == NULL || ctx == NULL || out == NULL) {
    return 1;
  }
  if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1 ||
      EVP_CIPHER_CTX_set_key_length(ctx, (int)key_len) != 1 ||
      EVP_EncryptInit_ex(ctx, NULL, NULL, key, NULL) != 1 ||
      EVP_EncryptUpdate(ctx, out, &produced, msg, (int)msg_len) != 1 ||
      EVP_EncryptFinal_ex(ctx, out + produced, &final_len) != 1) {
    return 1;
  }
  produced += final_len;
  for (i = 0; i < (size_t)produced; i++) {
    printf("%02x", out[i]);
  }
  printf("\n");
  return 0;
}
