/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * Constant-time gate, clean plant.
 *
 * Built against the library compiled with GSEC_CT_TEST and run under
 * memcheck. A conditional jump on a poisoned byte here means gsec_equal or
 * gsec_wipe leaked. Refuses to run outside Valgrind: without it the poison
 * marks are invisible and a green exit would mean nothing.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/hkdf.h>
#include <ghoti.io/security/pbkdf2.h>
#include <ghoti.io/security/hmac.h>
#include <ghoti.io/security/aes.h>
#include <ghoti.io/security/aes_cbc.h>
#include <ghoti.io/security/aes_ctr.h>
#include <ghoti.io/security/aes_gcm.h>
#include <ghoti.io/security/chacha20_poly1305.h>
#include <ghoti.io/security/ecdsa_p256.h>
#include <ghoti.io/security/ecdh_p256.h>
#include <ghoti.io/security/ed25519.h>
#include <ghoti.io/security/rsa.h>
#include <ghoti.io/security/x25519.h>
#include <ghoti.io/security/md5.h>
#include <ghoti.io/security/sha1.h>
#include <ghoti.io/security/sha256.h>
#include <ghoti.io/security/sha384.h>
#include <ghoti.io/security/sha512.h>

#include <string.h>
#include <valgrind/memcheck.h>

int main(void) {
  unsigned char a[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  unsigned char b[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  unsigned char secret[8];
  GSEC_Result result;
  size_t i;

  if (RUNNING_ON_VALGRIND == 0) {
    return 2;
  }

  gsec_poison(a, sizeof a);
  gsec_poison(b, sizeof b);
  result = gsec_equal(a, b, sizeof a);
  if (result != GSEC_OK) {
    return 3;
  }

  b[7] = 9;
  gsec_poison(b, sizeof b);
  result = gsec_equal(a, b, sizeof a);
  if (result != GSEC_ERR_MISMATCH) {
    return 4;
  }

  memset(secret, 0xA5, sizeof secret);
  gsec_poison(secret, sizeof secret);
  if (gsec_wipe(secret, sizeof secret) != GSEC_OK) {
    return 5;
  }
  for (i = 0; i < sizeof secret; i++) {
    if (secret[i] != 0) {
      return 6;
    }
  }

  /* The message is secret. A branch or a table index on one of its bytes
   * inside SHA-256 is the leak this run exists to report. The digest is a
   * function of that message, so it is wiped rather than inspected. */
  {
    unsigned char digest[GSEC_SHA256_DIGEST_LEN];

    gsec_poison(secret, sizeof secret);
    if (gsec_sha256(secret, sizeof secret, digest) != GSEC_OK) {
      return 7;
    }
    gsec_wipe(digest, sizeof digest);
  }
  {
    unsigned char digest[GSEC_SHA512_DIGEST_LEN];

    gsec_poison(secret, sizeof secret);
    if (gsec_sha512(secret, sizeof secret, digest) != GSEC_OK) {
      return 8;
    }
    gsec_wipe(digest, sizeof digest);
  }
  {
    unsigned char digest[GSEC_SHA384_DIGEST_LEN];

    gsec_poison(secret, sizeof secret);
    if (gsec_sha384(secret, sizeof secret, digest) != GSEC_OK) {
      return 9;
    }
    gsec_wipe(digest, sizeof digest);
  }
  {
    unsigned char digest[GSEC_SHA1_DIGEST_LEN];

    gsec_poison(secret, sizeof secret);
    if (gsec_sha1(secret, sizeof secret, digest) != GSEC_OK) {
      return 10;
    }
    gsec_wipe(digest, sizeof digest);
  }
  {
    unsigned char digest[GSEC_MD5_DIGEST_LEN];

    gsec_poison(secret, sizeof secret);
    if (gsec_md5(secret, sizeof secret, digest) != GSEC_OK) {
      return 14;
    }
    gsec_wipe(digest, sizeof digest);
  }
  {
    unsigned char block[GSEC_AES_BLOCK_LEN];
    unsigned char out[GSEC_AES_BLOCK_LEN];
    unsigned char key[GSEC_AES128_KEY_LEN];

    memset(block, 0x5a, sizeof block);
    memset(key, 0x3c, sizeof key);
    gsec_poison(key, sizeof key);
    gsec_poison(block, sizeof block);
    if (gsec_aes_encrypt(key, sizeof key, block, out) != GSEC_OK) {
      return 15;
    }
    gsec_wipe(out, sizeof out);
    gsec_wipe(key, sizeof key);
    gsec_wipe(block, sizeof block);
  }
  {
    unsigned char counter[GSEC_AES_BLOCK_LEN];
    unsigned char out[32];
    unsigned char key[GSEC_AES128_KEY_LEN];

    memset(counter, 1, sizeof counter);
    memset(key, 0x3c, sizeof key);
    gsec_poison(key, sizeof key);
    gsec_poison(secret, sizeof secret);
    if (gsec_aes_ctr(key, sizeof key, counter, GSEC_AES_CTR_BE, secret, out,
        sizeof secret) != GSEC_OK) {
      return 16;
    }
    gsec_wipe(out, sizeof out);
    gsec_wipe(key, sizeof key);
  }
  {
    unsigned char plain[GSEC_AES_BLOCK_LEN];
    unsigned char iv[GSEC_AES_BLOCK_LEN];
    unsigned char out[GSEC_AES_BLOCK_LEN];
    unsigned char key[GSEC_AES128_KEY_LEN];

    memset(plain, 0xa5, sizeof plain);
    memset(iv, 1, sizeof iv);
    memset(key, 0x3c, sizeof key);
    gsec_poison(key, sizeof key);
    gsec_poison(plain, sizeof plain);
    if (gsec_aes_cbc_encrypt(key, sizeof key, iv, plain, sizeof plain, out) !=
        GSEC_OK) {
      return 25;
    }
    gsec_wipe(out, sizeof out);
    gsec_wipe(plain, sizeof plain);
    gsec_wipe(key, sizeof key);
  }
  {
    unsigned char iv[12];
    unsigned char tag[16];
    unsigned char out[8];
    unsigned char key[GSEC_AES128_KEY_LEN];

    memset(iv, 2, sizeof iv);
    memset(key, 0x3c, sizeof key);
    gsec_poison(key, sizeof key);
    gsec_poison(secret, sizeof secret);
    if (gsec_aes_gcm_encrypt(key, sizeof key, iv, sizeof iv, secret,
        sizeof secret, secret, sizeof secret, out, tag, sizeof tag) !=
        GSEC_OK) {
      return 17;
    }
    gsec_wipe(out, sizeof out);
    gsec_wipe(tag, sizeof tag);
    gsec_wipe(key, sizeof key);
  }
  {
    unsigned char nonce[GSEC_CHACHA20_NONCE_LEN];
    unsigned char tag[GSEC_POLY1305_TAG_LEN];
    unsigned char out[8];
    unsigned char key[GSEC_CHACHA20_KEY_LEN];

    memset(nonce, 2, sizeof nonce);
    memset(key, 0x3c, sizeof key);
    gsec_poison(key, sizeof key);
    gsec_poison(secret, sizeof secret);
    if (gsec_chacha20_poly1305_encrypt(key, nonce, secret, sizeof secret,
        secret, sizeof secret, out, tag) != GSEC_OK) {
      return 18;
    }
    gsec_wipe(out, sizeof out);
    gsec_wipe(tag, sizeof tag);
    gsec_wipe(key, sizeof key);
  }
  {
    unsigned char scalar[GSEC_X25519_LEN];
    unsigned char point[GSEC_X25519_LEN];
    unsigned char out[GSEC_X25519_LEN];

    memset(scalar, 0x3c, sizeof scalar);
    memset(point, 0, sizeof point);
    point[0] = 9;
    gsec_poison(scalar, sizeof scalar);
    if (gsec_x25519(scalar, point, out) != GSEC_OK) {
      return 19;
    }
    gsec_wipe(out, sizeof out);
    gsec_wipe(scalar, sizeof scalar);
  }
  {
    unsigned char seed[GSEC_ED25519_LEN];
    unsigned char sig[GSEC_ED25519_SIG_LEN];
    static const unsigned char message[1] = {0x72};

    memset(seed, 0x3c, sizeof seed);
    gsec_poison(seed, sizeof seed);
    if (gsec_ed25519_sign(seed, message, sizeof message, sig) != GSEC_OK) {
      return 20;
    }
    gsec_wipe(sig, sizeof sig);
    gsec_wipe(seed, sizeof seed);
  }
  {
    unsigned char scalar[GSEC_P256_LEN];
    unsigned char peer[GSEC_P256_PUBLIC_LEN] = {
      0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
      0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
      0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
      0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
      0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
      0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
      0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
      0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
    };
    unsigned char out[GSEC_P256_LEN];

    memset(scalar, 0x3c, sizeof scalar);
    gsec_poison(scalar, sizeof scalar);
    if (gsec_ecdh_p256(scalar, peer, out) != GSEC_OK) {
      return 21;
    }
    gsec_wipe(out, sizeof out);
    gsec_wipe(scalar, sizeof scalar);
  }
  {
    unsigned char scalar[GSEC_ECDSA_P256_LEN];
    unsigned char sig[GSEC_ECDSA_P256_SIG_LEN];
    static const unsigned char message[1] = {0x72};

    memset(scalar, 0x3c, sizeof scalar);
    gsec_poison(scalar, sizeof scalar);
    if (gsec_ecdsa_p256_sign(scalar, message, sizeof message, sig) != GSEC_OK) {
      return 22;
    }
    gsec_wipe(sig, sizeof sig);
    gsec_wipe(scalar, sizeof scalar);
  }
  {
    static const unsigned char n[64] = {
      0xc8, 0x8a, 0xe1, 0x14, 0xb3, 0xe5, 0x6a, 0x6f,
      0x5e, 0xc5, 0x24, 0xd3, 0x3d, 0x15, 0xe5, 0x48,
      0xaf, 0x33, 0xb2, 0xcb, 0xc0, 0xcc, 0x0b, 0xaf,
      0x87, 0x2f, 0x53, 0xe5, 0x5a, 0x25, 0x53, 0xb2,
      0x26, 0x05, 0xc2, 0x31, 0x85, 0x8e, 0xe4, 0x73,
      0x03, 0xeb, 0xfd, 0x9d, 0x47, 0xe1, 0x8e, 0x1e,
      0x7b, 0x3c, 0xd4, 0x92, 0xe6, 0xd0, 0x9a, 0xc0,
      0xd2, 0x73, 0x3a, 0x4a, 0x45, 0x94, 0x83, 0x21
    };
    static const unsigned char e[3] = {0x01, 0x00, 0x01};
    unsigned char d[64] = {
      0xaf, 0xa3, 0x22, 0x9a, 0x75, 0x2c, 0x3a, 0x59,
      0xac, 0x10, 0xd1, 0xbd, 0xc8, 0x44, 0x42, 0xf9,
      0xb3, 0xa8, 0x7d, 0xb1, 0x81, 0xfb, 0xb3, 0x48,
      0x5a, 0x07, 0x93, 0x5c, 0xcd, 0xe4, 0xdf, 0x35,
      0x1a, 0xb5, 0x1b, 0xb6, 0x93, 0x92, 0x59, 0x2b,
      0xa0, 0x32, 0xf1, 0x36, 0xd3, 0x98, 0x28, 0xbf,
      0xda, 0xc4, 0x9a, 0xc3, 0x24, 0xd9, 0x71, 0xe9,
      0xbc, 0x31, 0x11, 0x7c, 0xa7, 0x33, 0x89, 0xd9
    };
    static const unsigned char message[1] = {0x72};
    static const unsigned char salt[8] = {
      0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
    };
    unsigned char sig[64];

    gsec_poison(d, sizeof d);
    if (gsec_rsa_private_pkcs1_v15_sign(GSEC_RSA_SHA256, n, sizeof n, e,
        sizeof e, d, sizeof d, message, sizeof message, sig,
        sizeof sig) != GSEC_OK) {
      return 23;
    }
    gsec_wipe(sig, sizeof sig);
    if (gsec_rsa_private_pss_sign(GSEC_RSA_SHA256, GSEC_RSA_SHA256, n, sizeof n,
        e, sizeof e, d, sizeof d, message, sizeof message, sig, sizeof sig,
        salt, sizeof salt) != GSEC_OK) {
      return 24;
    }
    gsec_wipe(sig, sizeof sig);
    gsec_wipe(d, sizeof d);
  }
  {
    unsigned char mac[GSEC_SHA256_DIGEST_LEN];
    unsigned char key[8];

    memset(key, 0x3c, sizeof key);
    gsec_poison(key, sizeof key);
    gsec_poison(secret, sizeof secret);
    if (gsec_hmac(GSEC_HMAC_SHA256, key, sizeof key, secret, sizeof secret,
        mac) != GSEC_OK) {
      return 11;
    }
    gsec_wipe(mac, sizeof mac);
    gsec_wipe(key, sizeof key);
  }
  {
    unsigned char okm[16];

    gsec_poison(secret, sizeof secret);
    if (gsec_hkdf(GSEC_HKDF_SHA256, NULL, 0, secret, sizeof secret, NULL, 0,
        okm, sizeof okm) != GSEC_OK) {
      return 12;
    }
    gsec_wipe(okm, sizeof okm);
  }
  {
    unsigned char dk[16];

    gsec_poison(secret, sizeof secret);
    if (gsec_pbkdf2(GSEC_PBKDF2_SHA1, secret, sizeof secret, NULL, 0, 2, dk,
        sizeof dk) != GSEC_OK) {
      return 13;
    }
    gsec_wipe(dk, sizeof dk);
  }
  return 0;
}
