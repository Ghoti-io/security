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
 * @file rsa.h
 *
 * RSA signatures and encryption. PKCS#1 v1.5 and PSS signatures, and
 * PKCS#1 v1.5 and OAEP encryption.
 *
 * The modulus is at most 4096 bits. A leading zero byte is ignored, which
 * is how an ASN.1 integer is written when its top bit is set. The
 * signature is the same length as the modulus after those zeros are
 * removed. PKCS#1 v1.5 accepts only the DER DigestInfo, including the
 * NULL, and at least eight 0xff padding bytes. PSS takes the salt length
 * as a parameter and encodes one bit shorter than the modulus, which is
 * what RFC 8017 specifies. MD5 and SHA-1 are accepted so an old
 * certificate can be checked and then rejected for the algorithm.
 *
 * Signing takes the private exponent as well as the public exponent. The
 * exponentiation does not branch on the private exponent, and each
 * signature is blinded with a fresh value from the kernel generator. The
 * blinding does not change the signature bytes: they are still the
 * encoded message raised to the private exponent. The PSS salt is the
 * caller's, the same rule as every other nonce in this library. A
 * modulus past 4096 bits is rejected.
 *
 * Encryption uses the same modulus rules. PKCS#1 v1.5 type 2 is what TLS
 * 1.2 RSA key transport decrypts, and the padding check does not branch on
 * the encoded message. OAEP is the same operation with the safer padding.
 * Neither uses the Chinese remainder theorem.
 */

#ifndef GHOTI_IO_GSEC_RSA_H
#define GHOTI_IO_GSEC_RSA_H

#include <ghoti.io/security/core.h>
#include <ghoti.io/security/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** MD5. Not collision resistant. */
#define GSEC_RSA_MD5 1u

/** SHA-1. Not collision resistant. */
#define GSEC_RSA_SHA1 2u

/** SHA-256. */
#define GSEC_RSA_SHA256 3u

/** SHA-384. */
#define GSEC_RSA_SHA384 4u

/** SHA-512. */
#define GSEC_RSA_SHA512 5u

/** Largest modulus, in bytes, after a leading zero is removed. */
#define GSEC_RSA_MODULUS_MAX 512u

/**
 * @brief Verify an RSASSA-PKCS1-v1_5 signature.
 *
 * @param hash ::GSEC_RSA_MD5, ::GSEC_RSA_SHA1, ::GSEC_RSA_SHA256,
 *   ::GSEC_RSA_SHA384, or ::GSEC_RSA_SHA512.
 * @param n Modulus, big-endian. A leading 0x00 is ignored.
 * @param n_len Length of @p n.
 * @param e Public exponent, big-endian. It must be odd and at least 3.
 * @param e_len Length of @p e.
 * @param msg Message. NULL only when @p msg_len is 0.
 * @param msg_len Message length in bytes.
 * @param sig Signature, big-endian, the same length as the modulus after
 *   a leading zero is removed.
 * @param sig_len Length of @p sig.
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH, ::GSEC_ERR_INVALID, or
 *   ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_rsa_pkcs1_v15_verify(uint32_t hash, const void * n,
    size_t n_len, const void * e, size_t e_len, const void * msg,
    size_t msg_len, const void * sig, size_t sig_len);

/**
 * @brief Verify an RSASSA-PSS signature.
 *
 * @p mgf_hash is the MGF1 hash. TLS uses the same hash as @p hash, and
 * the salt length equal to that hash's digest length.
 *
 * @param hash The message hash. One of the ids accepted by
 *   ::gsec_rsa_pkcs1_v15_verify.
 * @param mgf_hash The MGF1 hash. The same set.
 * @param n Modulus, big-endian. A leading 0x00 is ignored.
 * @param n_len Length of @p n.
 * @param e Public exponent, big-endian. It must be odd and at least 3.
 * @param e_len Length of @p e.
 * @param msg Message. NULL only when @p msg_len is 0.
 * @param msg_len Message length in bytes.
 * @param sig Signature, big-endian.
 * @param sig_len Length of @p sig.
 * @param salt_len Expected salt length in bytes.
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH, ::GSEC_ERR_INVALID, or
 *   ::GSEC_ERR_LIMIT.
 */
GSEC_API GSEC_Result gsec_rsa_pss_verify(uint32_t hash, uint32_t mgf_hash,
    const void * n, size_t n_len, const void * e, size_t e_len,
    const void * msg, size_t msg_len, const void * sig, size_t sig_len,
    size_t salt_len);

/**
 * @brief Sign with RSASSA-PKCS1-v1_5.
 *
 * @param hash The message hash. The same ids as
 *   ::gsec_rsa_pkcs1_v15_verify, including MD5 and SHA-1.
 * @param n Modulus, big-endian. A leading 0x00 is ignored.
 * @param n_len Length of @p n.
 * @param e Public exponent, big-endian. It must be odd and at least 3.
 *   Blinding raises the random factor to this exponent.
 * @param e_len Length of @p e.
 * @param d Private exponent, big-endian. A leading 0x00 is ignored. The
 *   integer must be nonzero and strictly less than the modulus. Up to
 *   eight leading zero bytes are accepted; a longer buffer is
 *   ::GSEC_ERR_LIMIT.
 * @param d_len Length of @p d.
 * @param msg Message. NULL only when @p msg_len is 0. Hashed before
 *   @p sig is written, so the two may alias.
 * @param msg_len Message length in bytes.
 * @param sig Signature buffer. Its length is the modulus length after a
 *   leading zero is removed. On failure that buffer is wiped.
 * @param sig_len Length of @p sig. Any other length is ::GSEC_ERR_INVALID.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, ::GSEC_ERR_LIMIT, ::GSEC_ERR_IO,
 *   or ::GSEC_ERR_INTERNAL. ::GSEC_ERR_IO means the kernel generator
 *   failed. ::GSEC_ERR_INTERNAL means eight blinding values were unusable.
 */
GSEC_API GSEC_Result gsec_rsa_private_pkcs1_v15_sign(uint32_t hash,
    const void * n, size_t n_len, const void * e, size_t e_len,
    const void * d, size_t d_len, const void * msg, size_t msg_len,
    void * sig, size_t sig_len);

/**
 * @brief Sign with RSASSA-PSS.
 *
 * @p salt is the caller's nonce. An empty salt is @p salt_len 0, and
 * @p salt may be NULL in that case. TLS uses @p mgf_hash equal to
 * @p hash and a salt as long as the digest.
 *
 * @param hash The message hash. The same ids as
 *   ::gsec_rsa_pkcs1_v15_verify.
 * @param mgf_hash The MGF1 hash. The same set.
 * @param n Modulus, big-endian. A leading 0x00 is ignored.
 * @param n_len Length of @p n.
 * @param e Public exponent, big-endian. Odd and at least 3.
 * @param e_len Length of @p e.
 * @param d Private exponent, big-endian. Same rules as
 *   ::gsec_rsa_private_pkcs1_v15_sign.
 * @param d_len Length of @p d.
 * @param msg Message. NULL only when @p msg_len is 0.
 * @param msg_len Message length in bytes.
 * @param sig Signature buffer, wiped on failure.
 * @param sig_len Length of @p sig, the stripped modulus length.
 * @param salt Salt bytes. NULL only when @p salt_len is 0.
 * @param salt_len Salt length in bytes.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, ::GSEC_ERR_LIMIT, ::GSEC_ERR_IO,
 *   or ::GSEC_ERR_INTERNAL.
 */
GSEC_API GSEC_Result gsec_rsa_private_pss_sign(uint32_t hash,
    uint32_t mgf_hash, const void * n, size_t n_len, const void * e,
    size_t e_len, const void * d, size_t d_len, const void * msg,
    size_t msg_len, void * sig, size_t sig_len, const void * salt,
    size_t salt_len);

/**
 * @brief Encrypt with RSAES-PKCS1-v1_5.
 *
 * The padding is random nonzero bytes from the kernel generator. The
 * message must be at least eleven bytes shorter than the stripped
 * modulus.
 *
 * @param n Modulus, big-endian. A leading 0x00 is ignored.
 * @param n_len Length of @p n.
 * @param e Public exponent, big-endian. Odd and at least 3.
 * @param e_len Length of @p e.
 * @param msg Message. NULL only when @p msg_len is 0.
 * @param msg_len Message length in bytes.
 * @param out Ciphertext buffer, the stripped modulus length. Wiped on
 *   failure.
 * @param out_len Length of @p out. Any other length is ::GSEC_ERR_INVALID.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, ::GSEC_ERR_LIMIT, or
 *   ::GSEC_ERR_IO.
 */
GSEC_API GSEC_Result gsec_rsa_pkcs1_v15_encrypt(const void * n, size_t n_len,
    const void * e, size_t e_len, const void * msg, size_t msg_len, void * out,
    size_t out_len);

/**
 * @brief Decrypt with RSAES-PKCS1-v1_5.
 *
 * The padding scan walks the whole encoded message and only then branches,
 * on the public answer. A bad padding and a ciphertext that is not the
 * modulus length are both ::GSEC_ERR_MISMATCH. @p msg is wiped on failure.
 *
 * @param n Modulus, big-endian. A leading 0x00 is ignored.
 * @param n_len Length of @p n.
 * @param e Public exponent, big-endian. Used to check the blinded result.
 * @param e_len Length of @p e.
 * @param d Private exponent, big-endian. Same rules as
 *   ::gsec_rsa_private_pkcs1_v15_sign.
 * @param d_len Length of @p d.
 * @param cipher Ciphertext, big-endian.
 * @param cipher_len Length of @p cipher.
 * @param msg Output buffer. May alias @p cipher.
 * @param msg_cap Capacity of @p msg. A message that does not fit is
 *   ::GSEC_ERR_LIMIT, and @p msg is wiped.
 * @param msg_len Receives the message length. Not written on failure.
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH, ::GSEC_ERR_INVALID,
 *   ::GSEC_ERR_LIMIT, ::GSEC_ERR_IO, or ::GSEC_ERR_INTERNAL.
 */
GSEC_API GSEC_Result gsec_rsa_pkcs1_v15_decrypt(const void * n, size_t n_len,
    const void * e, size_t e_len, const void * d, size_t d_len,
    const void * cipher, size_t cipher_len, void * msg, size_t msg_cap,
    size_t * msg_len);

/**
 * @brief Encrypt with RSAES-OAEP.
 *
 * @p hash is both the label hash and MGF1. An empty label is @p label_len
 * 0, and @p label may be NULL in that case. The message must be shorter
 * than the modulus by two digests plus two bytes.
 *
 * @param hash One of the ids accepted by ::gsec_rsa_pkcs1_v15_verify.
 * @param n Modulus, big-endian.
 * @param n_len Length of @p n.
 * @param e Public exponent, big-endian.
 * @param e_len Length of @p e.
 * @param label Label. NULL only when @p label_len is 0.
 * @param label_len Label length in bytes.
 * @param msg Message. NULL only when @p msg_len is 0.
 * @param msg_len Message length in bytes.
 * @param out Ciphertext buffer, the stripped modulus length. Wiped on
 *   failure.
 * @param out_len Length of @p out.
 * @return ::GSEC_OK, ::GSEC_ERR_INVALID, ::GSEC_ERR_LIMIT, or
 *   ::GSEC_ERR_IO.
 */
GSEC_API GSEC_Result gsec_rsa_oaep_encrypt(uint32_t hash, const void * n,
    size_t n_len, const void * e, size_t e_len, const void * label,
    size_t label_len, const void * msg, size_t msg_len, void * out,
    size_t out_len);

/**
 * @brief Decrypt with RSAES-OAEP.
 *
 * The label check and the 0x01 separator scan do not branch on the encoded
 * message. A bad label, bad padding, and a ciphertext of the wrong length
 * are all ::GSEC_ERR_MISMATCH. @p msg is wiped on failure.
 *
 * @param hash The hash used to encrypt. The same ids as
 *   ::gsec_rsa_oaep_encrypt.
 * @param n Modulus, big-endian.
 * @param n_len Length of @p n.
 * @param e Public exponent, big-endian.
 * @param e_len Length of @p e.
 * @param d Private exponent, big-endian.
 * @param d_len Length of @p d.
 * @param label Label. NULL only when @p label_len is 0. A different label
 *   from the one used to encrypt is ::GSEC_ERR_MISMATCH.
 * @param label_len Label length in bytes.
 * @param cipher Ciphertext, big-endian.
 * @param cipher_len Length of @p cipher.
 * @param msg Output buffer. May alias @p cipher.
 * @param msg_cap Capacity of @p msg.
 * @param msg_len Receives the message length. Not written on failure.
 * @return ::GSEC_OK, ::GSEC_ERR_MISMATCH, ::GSEC_ERR_INVALID,
 *   ::GSEC_ERR_LIMIT, ::GSEC_ERR_IO, or ::GSEC_ERR_INTERNAL.
 */
GSEC_API GSEC_Result gsec_rsa_oaep_decrypt(uint32_t hash, const void * n,
    size_t n_len, const void * e, size_t e_len, const void * d, size_t d_len,
    const void * label, size_t label_len, const void * cipher,
    size_t cipher_len, void * msg, size_t msg_cap, size_t * msg_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GSEC_RSA_H */
