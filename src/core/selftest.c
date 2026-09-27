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
 * Known answers an embedder can run without the test suite.
 *
 * The bytes below are not secret. They are fixed inputs, and nothing here
 * writes them anywhere except into stack buffers that are wiped before return.
 */

#include <ghoti.io/security/macros.h>

#include <ghoti.io/security/hkdf.h>
#include <ghoti.io/security/pbkdf2.h>
#include <ghoti.io/security/hmac.h>
#include <ghoti.io/security/random.h>
#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/selftest.h>
#include <ghoti.io/security/sha1.h>
#include <ghoti.io/security/sha256.h>
#include <ghoti.io/security/sha384.h>
#include <ghoti.io/security/sha512.h>

GSEC_Result gsec_selftest(void) {
  static const unsigned char left[4] = {0x00, 0x01, 0x02, 0x03};
  static const unsigned char right[4] = {0x00, 0x01, 0x02, 0x04};
  unsigned char buffer[32];
  unsigned char drawn[32];
  size_t i;
  GSEC_Result result;
  unsigned char changed;

  result = gsec_equal(NULL, NULL, 0);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_equal(left, left, sizeof left);
  if (result != GSEC_OK) {
    return result;
  }
  result = gsec_equal(left, right, sizeof left);
  if (result != GSEC_ERR_MISMATCH) {
    return result == GSEC_OK ? GSEC_ERR_INTERNAL : result;
  }

  for (i = 0; i < sizeof buffer; i++) {
    buffer[i] = 0xA5;
  }
  result = gsec_wipe(buffer, sizeof buffer);
  if (result != GSEC_OK) {
    return result;
  }
  for (i = 0; i < sizeof buffer; i++) {
    if (buffer[i] != 0) {
      return GSEC_ERR_INTERNAL;
    }
  }

  for (i = 0; i < sizeof drawn; i++) {
    drawn[i] = 0xA5;
  }
  result = gsec_random_bytes(drawn, sizeof drawn, NULL);
  if (result != GSEC_OK) {
    return result;
  }
  /* 32 bytes of 0xA5 from the kernel is a possible output. It is not a
   * plausible one, and a generator that failed to write would leave exactly
   * that pattern. Every byte is folded in: stopping at the first difference
   * would be the timing leak this library exists not to write, and the bytes
   * are key material until the wipe below. */
  changed = 0;
  for (i = 0; i < sizeof drawn; i++) {
    changed = (unsigned char)(changed | (unsigned char)(drawn[i] ^ 0xA5));
  }
  result = gsec_wipe(drawn, sizeof drawn);
  if (result != GSEC_OK) {
    return result;
  }
  if (changed == 0) {
    return GSEC_ERR_INTERNAL;
  }

  /* RFC 6234 section 8.1. Empty, and "abc" absorbed one byte at a time,
   * which is the padding boundary the one-shot call does not exercise. */
  {
    static const unsigned char empty_dig[GSEC_SHA256_DIGEST_LEN] = {
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,
      0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
      0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    static const unsigned char abc_dig[GSEC_SHA256_DIGEST_LEN] = {
      0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
      0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
      0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    static const unsigned char abc_msg[3] = {0x61, 0x62, 0x63};
    unsigned char dig[GSEC_SHA256_DIGEST_LEN];
    GSEC_Sha256 ctx;

    result = gsec_sha256(NULL, 0, dig);
    if (result != GSEC_OK) {
      return result;
    }
    result = gsec_equal(dig, empty_dig, sizeof dig);
    gsec_wipe(dig, sizeof dig);
    if (result != GSEC_OK) {
      return result == GSEC_ERR_MISMATCH ? GSEC_ERR_INTERNAL : result;
    }

    result = gsec_sha256_init(&ctx);
    if (result != GSEC_OK) {
      return result;
    }
    for (i = 0; i < sizeof abc_msg; i++) {
      result = gsec_sha256_update(&ctx, abc_msg + i, 1);
      if (result != GSEC_OK) {
        gsec_wipe(&ctx, sizeof ctx);
        return result;
      }
    }
    result = gsec_sha256_final(&ctx, dig);
    if (result != GSEC_OK) {
      gsec_wipe(&ctx, sizeof ctx);
      return result;
    }
    result = gsec_equal(dig, abc_dig, sizeof dig);
    gsec_wipe(dig, sizeof dig);
    if (result != GSEC_OK) {
      return result == GSEC_ERR_MISMATCH ? GSEC_ERR_INTERNAL : result;
    }
  }

  /* RFC 6234 sections 8.3 and 8.4. Same two messages, both widths. */
  {
    static const unsigned char sha512_empty[GSEC_SHA512_DIGEST_LEN] = {
      0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
      0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
      0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
      0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
      0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
      0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
      0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
      0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
    };
    static const unsigned char sha512_abc[GSEC_SHA512_DIGEST_LEN] = {
      0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
      0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
      0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
      0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
      0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
      0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
      0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
      0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
    };
    static const unsigned char sha384_empty[GSEC_SHA384_DIGEST_LEN] = {
      0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
      0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
      0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
      0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
      0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
      0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b
    };
    static const unsigned char sha384_abc[GSEC_SHA384_DIGEST_LEN] = {
      0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
      0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
      0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
      0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
      0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
      0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7
    };
    static const unsigned char abc_msg[3] = {0x61, 0x62, 0x63};
    unsigned char dig512[GSEC_SHA512_DIGEST_LEN];
    unsigned char dig384[GSEC_SHA384_DIGEST_LEN];
    GSEC_Sha512 ctx512;
    GSEC_Sha384 ctx384;

    result = gsec_sha512(NULL, 0, dig512);
    if (result != GSEC_OK) {
      return result;
    }
    result = gsec_equal(dig512, sha512_empty, sizeof dig512);
    gsec_wipe(dig512, sizeof dig512);
    if (result != GSEC_OK) {
      return result == GSEC_ERR_MISMATCH ? GSEC_ERR_INTERNAL : result;
    }

    result = gsec_sha512_init(&ctx512);
    if (result != GSEC_OK) {
      return result;
    }
    for (i = 0; i < sizeof abc_msg; i++) {
      result = gsec_sha512_update(&ctx512, abc_msg + i, 1);
      if (result != GSEC_OK) {
        gsec_wipe(&ctx512, sizeof ctx512);
        return result;
      }
    }
    result = gsec_sha512_final(&ctx512, dig512);
    if (result != GSEC_OK) {
      gsec_wipe(&ctx512, sizeof ctx512);
      return result;
    }
    result = gsec_equal(dig512, sha512_abc, sizeof dig512);
    gsec_wipe(dig512, sizeof dig512);
    if (result != GSEC_OK) {
      return result == GSEC_ERR_MISMATCH ? GSEC_ERR_INTERNAL : result;
    }

    result = gsec_sha384(NULL, 0, dig384);
    if (result != GSEC_OK) {
      return result;
    }
    result = gsec_equal(dig384, sha384_empty, sizeof dig384);
    gsec_wipe(dig384, sizeof dig384);
    if (result != GSEC_OK) {
      return result == GSEC_ERR_MISMATCH ? GSEC_ERR_INTERNAL : result;
    }

    result = gsec_sha384_init(&ctx384);
    if (result != GSEC_OK) {
      return result;
    }
    for (i = 0; i < sizeof abc_msg; i++) {
      result = gsec_sha384_update(&ctx384, abc_msg + i, 1);
      if (result != GSEC_OK) {
        gsec_wipe(&ctx384, sizeof ctx384);
        return result;
      }
    }
    result = gsec_sha384_final(&ctx384, dig384);
    if (result != GSEC_OK) {
      gsec_wipe(&ctx384, sizeof ctx384);
      return result;
    }
    result = gsec_equal(dig384, sha384_abc, sizeof dig384);
    gsec_wipe(dig384, sizeof dig384);
    if (result != GSEC_OK) {
      return result == GSEC_ERR_MISMATCH ? GSEC_ERR_INTERNAL : result;
    }
  }

  /* RFC 3174. SHA-1 is not collision resistant; the known answer is still
   * the check that this implementation is the function the caller asked for. */
  {
    static const unsigned char sha1_empty[GSEC_SHA1_DIGEST_LEN] = {
      0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
      0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
      0xaf, 0xd8, 0x07, 0x09
    };
    static const unsigned char sha1_abc[GSEC_SHA1_DIGEST_LEN] = {
      0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
      0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
      0x9c, 0xd0, 0xd8, 0x9d
    };
    static const unsigned char abc_msg[3] = {0x61, 0x62, 0x63};
    unsigned char dig[GSEC_SHA1_DIGEST_LEN];
    GSEC_Sha1 ctx;

    result = gsec_sha1(NULL, 0, dig);
    if (result != GSEC_OK) {
      return result;
    }
    result = gsec_equal(dig, sha1_empty, sizeof dig);
    gsec_wipe(dig, sizeof dig);
    if (result != GSEC_OK) {
      return result == GSEC_ERR_MISMATCH ? GSEC_ERR_INTERNAL : result;
    }

    result = gsec_sha1_init(&ctx);
    if (result != GSEC_OK) {
      return result;
    }
    for (i = 0; i < sizeof abc_msg; i++) {
      result = gsec_sha1_update(&ctx, abc_msg + i, 1);
      if (result != GSEC_OK) {
        gsec_wipe(&ctx, sizeof ctx);
        return result;
      }
    }
    result = gsec_sha1_final(&ctx, dig);
    if (result != GSEC_OK) {
      gsec_wipe(&ctx, sizeof ctx);
      return result;
    }
    result = gsec_equal(dig, sha1_abc, sizeof dig);
    gsec_wipe(dig, sizeof dig);
    if (result != GSEC_OK) {
      return result == GSEC_ERR_MISMATCH ? GSEC_ERR_INTERNAL : result;
    }
  }

  /* RFC 4231 test case 1, and a MAC that differs in the last byte. */
  {
    static const unsigned char key[20] = {
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    static const unsigned char msg[8] = {
      0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65
    };
    static const unsigned char mac[GSEC_SHA256_DIGEST_LEN] = {
      0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
      0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
      0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
      0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    };
    unsigned char got[GSEC_SHA256_DIGEST_LEN];
    unsigned char bad[GSEC_SHA256_DIGEST_LEN];

    result = gsec_hmac(GSEC_HMAC_SHA256, key, sizeof key, msg, sizeof msg, got);
    if (result != GSEC_OK) {
      return result;
    }
    result = gsec_equal(got, mac, sizeof got);
    gsec_wipe(got, sizeof got);
    if (result != GSEC_OK) {
      return result == GSEC_ERR_MISMATCH ? GSEC_ERR_INTERNAL : result;
    }
    for (i = 0; i < sizeof bad; i++) {
      bad[i] = mac[i];
    }
    bad[sizeof bad - 1] = (unsigned char)(bad[sizeof bad - 1] ^ 0x01u);
    result = gsec_hmac_verify(GSEC_HMAC_SHA256, key, sizeof key, msg,
        sizeof msg, bad, sizeof bad);
    gsec_wipe(bad, sizeof bad);
    if (result != GSEC_ERR_MISMATCH) {
      return result == GSEC_OK ? GSEC_ERR_INTERNAL : result;
    }
  }

  /* RFC 5869 test case 1. HKDF is not PBKDF2. */
  {
    static const unsigned char ikm[22] = {
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    static const unsigned char salt[13] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
      0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    static const unsigned char info[10] = {
      0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9
    };
    static const unsigned char okm[42] = {
      0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
      0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
      0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34,
      0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
    };
    unsigned char got[42];

    result = gsec_hkdf(GSEC_HKDF_SHA256, salt, sizeof salt, ikm, sizeof ikm,
        info, sizeof info, got, sizeof got);
    if (result != GSEC_OK) {
      return result;
    }
    result = gsec_equal(got, okm, sizeof got);
    gsec_wipe(got, sizeof got);
    if (result != GSEC_OK) {
      return result == GSEC_ERR_MISMATCH ? GSEC_ERR_INTERNAL : result;
    }
  }

  /* RFC 6070, one iteration. PBKDF2 is not HKDF. */
  {
    static const unsigned char password[8] = {
      0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64
    };
    static const unsigned char salt[4] = {0x73, 0x61, 0x6c, 0x74};
    static const unsigned char dk[20] = {
      0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9,
      0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6
    };
    unsigned char got[20];

    result = gsec_pbkdf2(GSEC_PBKDF2_SHA1, password, sizeof password, salt,
        sizeof salt, 1, got, sizeof got);
    if (result != GSEC_OK) {
      return result;
    }
    result = gsec_equal(got, dk, sizeof got);
    gsec_wipe(got, sizeof got);
    if (result != GSEC_OK) {
      return result == GSEC_ERR_MISMATCH ? GSEC_ERR_INTERNAL : result;
    }
  }
  return GSEC_OK;
}
