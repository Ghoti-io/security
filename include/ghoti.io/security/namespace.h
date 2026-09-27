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
 * @file namespace.h
 *
 * Maps every public name of this library into its version namespace.
 *
 * Kept in one file rather than beside each declaration: a type rename has to
 * be in effect before any struct tag that uses the name, and an internal
 * header may define such a tag without including the public header that
 * declares the typedef.
 *
 * `make check-symbols` fails if an exported symbol is missing from this list.
 *
 * See CONVENTIONS.md section 4.
 */

#ifndef GHOTI_IO_GSEC_NAMESPACE_H
#define GHOTI_IO_GSEC_NAMESPACE_H

#include <ghoti.io/security/libver.h>

/// @cond HIDDEN_SYMBOLS

/* Public types. GCU_* names are cutil's; cutil has already renamed them. */
#define GSEC_Aes GHOTIIO_SECURITY(GSEC_Aes)
#define GSEC_Aes_Ctr GHOTIIO_SECURITY(GSEC_Aes_Ctr)
#define GSEC_Allocator GHOTIIO_SECURITY(GSEC_Allocator)
#define GSEC_Hmac GHOTIIO_SECURITY(GSEC_Hmac)
#define GSEC_Limits GHOTIIO_SECURITY(GSEC_Limits)
#define GSEC_Md5 GHOTIIO_SECURITY(GSEC_Md5)
#define GSEC_Result GHOTIIO_SECURITY(GSEC_Result)
#define GSEC_Sha1 GHOTIIO_SECURITY(GSEC_Sha1)
#define GSEC_Sha256 GHOTIIO_SECURITY(GSEC_Sha256)
#define GSEC_Sha384 GHOTIIO_SECURITY(GSEC_Sha384)
#define GSEC_Sha512 GHOTIIO_SECURITY(GSEC_Sha512)

#define gsec_aes_decrypt GHOTIIO_SECURITY(gsec_aes_decrypt)
#define gsec_aes_decrypt_block GHOTIIO_SECURITY(gsec_aes_decrypt_block)
#define gsec_aes_encrypt GHOTIIO_SECURITY(gsec_aes_encrypt)
#define gsec_aes_encrypt_block GHOTIIO_SECURITY(gsec_aes_encrypt_block)
#define gsec_aes_encrypt_init GHOTIIO_SECURITY(gsec_aes_encrypt_init)
#define gsec_aes_encrypt_wipe GHOTIIO_SECURITY(gsec_aes_encrypt_wipe)
#define gsec_aes_ctr GHOTIIO_SECURITY(gsec_aes_ctr)
#define gsec_aes_ctr_init GHOTIIO_SECURITY(gsec_aes_ctr_init)
#define gsec_aes_ctr_update GHOTIIO_SECURITY(gsec_aes_ctr_update)
#define gsec_aes_ctr_wipe GHOTIIO_SECURITY(gsec_aes_ctr_wipe)
#define gsec_aes_cbc_decrypt GHOTIIO_SECURITY(gsec_aes_cbc_decrypt)
#define gsec_aes_cbc_encrypt GHOTIIO_SECURITY(gsec_aes_cbc_encrypt)
#define gsec_aes_gcm_decrypt GHOTIIO_SECURITY(gsec_aes_gcm_decrypt)
#define gsec_aes_gcm_encrypt GHOTIIO_SECURITY(gsec_aes_gcm_encrypt)
#define gsec_chacha20_poly1305_decrypt GHOTIIO_SECURITY(gsec_chacha20_poly1305_decrypt)
#define gsec_chacha20_poly1305_encrypt GHOTIIO_SECURITY(gsec_chacha20_poly1305_encrypt)
#define gsec_des_cbc_decrypt GHOTIIO_SECURITY(gsec_des_cbc_decrypt)
#define gsec_des_cbc_encrypt GHOTIIO_SECURITY(gsec_des_cbc_encrypt)
#define gsec_des_decrypt GHOTIIO_SECURITY(gsec_des_decrypt)
#define gsec_des_ede3_cbc_decrypt GHOTIIO_SECURITY(gsec_des_ede3_cbc_decrypt)
#define gsec_des_ede3_cbc_encrypt GHOTIIO_SECURITY(gsec_des_ede3_cbc_encrypt)
#define gsec_des_ede3_decrypt GHOTIIO_SECURITY(gsec_des_ede3_decrypt)
#define gsec_des_ede3_encrypt GHOTIIO_SECURITY(gsec_des_ede3_encrypt)
#define gsec_des_encrypt GHOTIIO_SECURITY(gsec_des_encrypt)
#define gsec_ecdsa_p256_public GHOTIIO_SECURITY(gsec_ecdsa_p256_public)
#define gsec_ecdsa_p256_sign GHOTIIO_SECURITY(gsec_ecdsa_p256_sign)
#define gsec_ecdsa_p256_verify GHOTIIO_SECURITY(gsec_ecdsa_p256_verify)
#define gsec_ecdh_p256 GHOTIIO_SECURITY(gsec_ecdh_p256)
#define gsec_ecdh_p256_public GHOTIIO_SECURITY(gsec_ecdh_p256_public)
#define gsec_ed25519_public GHOTIIO_SECURITY(gsec_ed25519_public)
#define gsec_ed25519_sign GHOTIIO_SECURITY(gsec_ed25519_sign)
#define gsec_ed25519_verify GHOTIIO_SECURITY(gsec_ed25519_verify)
#define gsec_allocator_default GHOTIIO_SECURITY(gsec_allocator_default)
#define gsec_equal GHOTIIO_SECURITY(gsec_equal)
#define gsec_hmac GHOTIIO_SECURITY(gsec_hmac)
#define gsec_hmac_final GHOTIIO_SECURITY(gsec_hmac_final)
#define gsec_hmac_init GHOTIIO_SECURITY(gsec_hmac_init)
#define gsec_hmac_update GHOTIIO_SECURITY(gsec_hmac_update)
#define gsec_hmac_verify GHOTIIO_SECURITY(gsec_hmac_verify)
#define gsec_hkdf GHOTIIO_SECURITY(gsec_hkdf)
#define gsec_hkdf_expand GHOTIIO_SECURITY(gsec_hkdf_expand)
#define gsec_hkdf_extract GHOTIIO_SECURITY(gsec_hkdf_extract)
#define gsec_limits_default GHOTIIO_SECURITY(gsec_limits_default)
#define gsec_md5 GHOTIIO_SECURITY(gsec_md5)
#define gsec_md5_final GHOTIIO_SECURITY(gsec_md5_final)
#define gsec_md5_init GHOTIIO_SECURITY(gsec_md5_init)
#define gsec_md5_update GHOTIIO_SECURITY(gsec_md5_update)
#define gsec_pbkdf2 GHOTIIO_SECURITY(gsec_pbkdf2)
#define gsec_poison GHOTIIO_SECURITY(gsec_poison)
#define gsec_random_bytes GHOTIIO_SECURITY(gsec_random_bytes)
#define gsec_rc4 GHOTIIO_SECURITY(gsec_rc4)
#define gsec_result_string GHOTIIO_SECURITY(gsec_result_string)
#define gsec_rsa_pkcs1_v15_verify GHOTIIO_SECURITY(gsec_rsa_pkcs1_v15_verify)
#define gsec_rsa_private_pkcs1_v15_sign GHOTIIO_SECURITY(gsec_rsa_private_pkcs1_v15_sign)
#define gsec_rsa_private_pss_sign GHOTIIO_SECURITY(gsec_rsa_private_pss_sign)
#define gsec_rsa_pss_verify GHOTIIO_SECURITY(gsec_rsa_pss_verify)
#define gsec_scrypt GHOTIIO_SECURITY(gsec_scrypt)
#define gsec_selftest GHOTIIO_SECURITY(gsec_selftest)
#define gsec_sha1 GHOTIIO_SECURITY(gsec_sha1)
#define gsec_sha1_final GHOTIIO_SECURITY(gsec_sha1_final)
#define gsec_sha1_init GHOTIIO_SECURITY(gsec_sha1_init)
#define gsec_sha1_update GHOTIIO_SECURITY(gsec_sha1_update)
#define gsec_sha256 GHOTIIO_SECURITY(gsec_sha256)
#define gsec_sha256_final GHOTIIO_SECURITY(gsec_sha256_final)
#define gsec_sha256_init GHOTIIO_SECURITY(gsec_sha256_init)
#define gsec_sha256_update GHOTIIO_SECURITY(gsec_sha256_update)
#define gsec_sha384 GHOTIIO_SECURITY(gsec_sha384)
#define gsec_sha384_final GHOTIIO_SECURITY(gsec_sha384_final)
#define gsec_sha384_init GHOTIIO_SECURITY(gsec_sha384_init)
#define gsec_sha384_update GHOTIIO_SECURITY(gsec_sha384_update)
#define gsec_sha512 GHOTIIO_SECURITY(gsec_sha512)
#define gsec_sha512_final GHOTIIO_SECURITY(gsec_sha512_final)
#define gsec_sha512_init GHOTIIO_SECURITY(gsec_sha512_init)
#define gsec_sha512_update GHOTIIO_SECURITY(gsec_sha512_update)
#define gsec_unpoison GHOTIIO_SECURITY(gsec_unpoison)
#define gsec_version_number GHOTIIO_SECURITY(gsec_version_number)
#define gsec_version_string GHOTIIO_SECURITY(gsec_version_string)
#define gsec_wipe GHOTIIO_SECURITY(gsec_wipe)
#define gsec_x25519 GHOTIIO_SECURITY(gsec_x25519)
#define gsec_x25519_public GHOTIIO_SECURITY(gsec_x25519_public)

/// @endcond

#endif /* GHOTI_IO_GSEC_NAMESPACE_H */
