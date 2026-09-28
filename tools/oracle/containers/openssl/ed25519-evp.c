/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * Verify an Ed25519 signature through OpenSSL's EVP.
 *
 * `openssl pkeyutl -verify -rawin` refuses a zero-length message. This
 * program does not. `ed25519-evp pure|ctx|ph <hexpk> <hexsig> <hexctx|->
 * <hexmsg|->` exits 0 when the signature is accepted.
 */

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

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

static int parse(const char * text, unsigned char ** out, size_t * n, size_t cap) {
  size_t len;
  size_t i;

  if (strcmp(text, "-") == 0) {
    *out = NULL;
    *n = 0;
    return 1;
  }
  len = strlen(text);
  if ((len % 2u) != 0 || len / 2u > cap) {
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
  unsigned char * public = NULL;
  unsigned char * signature = NULL;
  unsigned char * context = NULL;
  unsigned char * message = NULL;
  size_t public_len = 0;
  size_t signature_len = 0;
  size_t context_len = 0;
  size_t message_len = 0;
  const char * instance;
  EVP_PKEY * key = NULL;
  EVP_MD_CTX * md = NULL;
  EVP_PKEY_CTX * pctx = NULL;
  OSSL_PARAM params[3];
  int count = 0;
  int ok = 0;

  if (argc != 6) {
    fprintf(stderr, "usage: ed25519-evp pure|ctx|ph <hexpk> <hexsig> <hexctx|-> <hexmsg|->\n");
    return 2;
  }
  if (strcmp(argv[1], "pure") == 0) {
    instance = "Ed25519";
  } else if (strcmp(argv[1], "ctx") == 0) {
    instance = "Ed25519ctx";
  } else if (strcmp(argv[1], "ph") == 0) {
    instance = "Ed25519ph";
  } else {
    return 2;
  }
  if (!parse(argv[2], &public, &public_len, 32) || public_len != 32 ||
      !parse(argv[3], &signature, &signature_len, 64) || signature_len != 64 ||
      !parse(argv[4], &context, &context_len, 255) ||
      !parse(argv[5], &message, &message_len, 1024)) {
    free(public);
    free(signature);
    free(context);
    free(message);
    return 2;
  }
  key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public, public_len);
  md = EVP_MD_CTX_new();
  if (key == NULL || md == NULL ||
      EVP_DigestVerifyInit(md, &pctx, NULL, NULL, key) != 1) {
    goto done;
  }
  params[count++] = OSSL_PARAM_construct_utf8_string(
      OSSL_SIGNATURE_PARAM_INSTANCE, (char *)instance, 0);
  if (context_len > 0) {
    params[count++] = OSSL_PARAM_construct_octet_string(
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING, context, context_len);
  }
  params[count] = OSSL_PARAM_construct_end();
  if (EVP_PKEY_CTX_set_params(pctx, params) != 1) {
    goto done;
  }
  ok = EVP_DigestVerify(md, signature, signature_len,
      message == NULL ? (const unsigned char *)"" : message, message_len) == 1;

done:
  EVP_MD_CTX_free(md);
  EVP_PKEY_free(key);
  free(public);
  free(signature);
  free(context);
  free(message);
  return ok ? 0 : 1;
}
