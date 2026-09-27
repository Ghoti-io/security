# Ghoti.io Security

Cryptographic primitives: hashes, MACs, key derivation, authenticated
encryption, key agreement, signatures, and the entropy call. Strict DER,
PEM, PKCS#8 including PBES2, PKCS#12, X.509 including issuance, a parsed
CRL, and a parsed OCSP response live here until a certificates library
takes them. Fetching revocation and enumerating an operating-system trust
store stay with the caller. It does not hold a handshake or policy.
`certificates` and `tls` are the libraries those belong in.

## What is implemented

Phase 0, the machinery the algorithms are measured against, SHA-256, SHA-512,
SHA-384, SHA-1, MD5, HMAC over the four SHA hashes, HKDF, and PBKDF2. SHA-1 does
not provide collision resistance; it is here for ZIP and for old certificate
chains. MD5 does not either. It is here because an ICC profile identifier is
an MD5, and because an old certificate signed with it still has to be hashed
so the algorithm can be rejected for that reason. HMAC does not take MD5.
HKDF is the high-entropy derivation. PBKDF2 is the slow one, for a
password, which is what WinZip AES uses. AES-128, AES-192, and AES-256,
CTR, CBC, GCM, and ChaCha20-Poly1305 are implemented. CBC does not
authenticate, the length is a multiple of the block, and the
initialization vector is the caller's. ChaCha20-Poly1305 takes a
32-byte key, a 12-byte nonce, and a 16-byte tag. Decrypt wipes the plaintext
when the tag does not match. Nonce reuse under one key destroys authentication.
X25519 takes a 32-byte scalar and a 32-byte u-coordinate. The scalar is
clamped inside the function. A shared secret of all zeros is rejected and
the output is wiped. Ed25519 takes a 32-byte seed. The signature is 64
bytes. Verification rejects a point that is not canonical and an S that is
not strictly less than the group order. P-256 ECDH takes a 32-byte scalar
and a 64-byte public key, x then y. A coordinate that is not strictly less
than the prime, a point that is not on the curve, and the point at infinity
are rejected and the output is wiped. ECDSA P-256 takes a 32-byte scalar.
The signature is 64 bytes, r then s. Signing hashes with SHA-256 and uses
RFC 6979, and the s it emits is the low one. Verification accepts a high s.
An r or s of zero, or one that is not strictly less than the group order,
does not verify. RSA verification takes a modulus of at most 4096 bits
and an odd public exponent of at least 3. PKCS#1 v1.5 accepts only the DER
DigestInfo. PSS takes a salt length and encodes one bit shorter than
the modulus. MD5 and SHA-1 are there for old certificates. Signing
takes the private exponent as well. The exponentiation does not branch on
it, and each signature is blinded with a value from the kernel generator.
The blinding does not change the signature bytes. The PSS salt is the
caller's. A failure wipes the signature buffer. AES-CBC, DES, three-key
Triple DES, and RC4 are implemented for old formats. DES and RC4 are
broken and are not constant-time. AES-CBC does not authenticate. scrypt,
bcrypt, and Argon2 are password hashes for storage. They are not PBKDF2,
and none of the three is constant-time. ECDSA P-384 is the same contract
as P-256 with SHA-384 and 48-byte coordinates.

- `gsec_equal` compares two regions and returns `GSEC_OK` or `GSEC_ERR_MISMATCH`. A wrong tag is a status, not a boolean.
- `gsec_wipe` overwrites a region through a volatile store, so a later optimisation pass cannot delete the write.
- `gsec_random_bytes` reads the kernel generator. A failure wipes what was already written and returns `GSEC_ERR_IO`. There is no userspace generator behind that failure.
- `gsec_sha256` hashes a buffer. `gsec_sha256_init`, `gsec_sha256_update`, and `gsec_sha256_final` hash a message in slices. Final wipes the context. `gsec_sha512`, `gsec_sha384`, `gsec_sha1`, and `gsec_md5` are the same shape. SHA-384 is SHA-512's compression with a different initial value, not a truncation of a SHA-512 digest. MD5 is little-endian and is not a MAC.
- `gsec_hmac` is HMAC over one of those hashes. `gsec_hmac_verify` compares the MAC with `gsec_equal` and returns `GSEC_ERR_MISMATCH` when it differs.
- `gsec_hkdf` is HKDF over one of those hashes: extract, then expand. A salt of length zero is HashLen zero bytes. An output longer than 255 digests is `GSEC_ERR_LIMIT`. This is the high-entropy derivation.
- `gsec_pbkdf2` is PBKDF2 over one of those hashes. The iteration count is the cost, and zero is `GSEC_ERR_INVALID`. This is the slow derivation for a password. It is a different function from `gsec_hkdf`.
- `gsec_aes_encrypt` and `gsec_aes_decrypt` are one AES block at 128, 192, or 256 bits. The schedule from `gsec_aes_encrypt_init` serves both directions. A key byte is not a table index.
- `gsec_aes_ctr` is that block cipher in CTR. `GSEC_AES_CTR_BE` is the NIST counter. `GSEC_AES_CTR_LE` is the WinZip counter.
- `gsec_aes_gcm_encrypt` and `gsec_aes_gcm_decrypt` are AES-GCM. Decrypt wipes the plaintext when the tag does not match. Nonce reuse under one key destroys authentication.
- `gsec_chacha20_poly1305_encrypt` and `gsec_chacha20_poly1305_decrypt` are AEAD_CHACHA20_POLY1305. The key, nonce, and tag lengths are fixed. Decrypt wipes the plaintext when the tag does not match. Nonce reuse under one key destroys authentication.
- `gsec_x25519` multiplies a scalar by a peer u-coordinate. `gsec_x25519_public` multiplies it by the base point. Both lengths are fixed at 32 bytes. The all-zero shared secret is rejected and the output is wiped.
- `gsec_ed25519_public` derives a public key from a 32-byte seed. `gsec_ed25519_sign` signs a message. `gsec_ed25519_verify` returns `GSEC_ERR_MISMATCH` for a bad signature, a non-canonical point, or an S that is not strictly less than the group order.
- `gsec_ecdh_p256` multiplies a scalar by a peer point and writes the shared x coordinate. `gsec_ecdh_p256_public` multiplies it by the base point. A bad point and the point at infinity are `GSEC_ERR_INVALID`, and the output is wiped. `gsec_ecdh_p384` and `gsec_ecdh_p384_public` are the same contract on P-384, with a 48-byte scalar and a 96-byte point.
- `gsec_ecdsa_p256_public` multiplies a scalar by the base point. `gsec_ecdsa_p256_sign` signs a message and emits the low s. `gsec_ecdsa_p256_verify` returns `GSEC_ERR_MISMATCH` for a bad signature, a bad point, or an r or s that is zero or not strictly less than the group order. A high s verifies.
- `gsec_rsa_pkcs1_v15_verify` and `gsec_rsa_pss_verify` check a signature with the public exponent. A modulus past 4096 bits is `GSEC_ERR_LIMIT`.
- `gsec_rsa_private_pkcs1_v15_sign` and `gsec_rsa_private_pss_sign` produce that signature. The private exponent is raised in constant time and the base is blinded. The PSS salt is the caller's. Eight unusable blinding values are `GSEC_ERR_INTERNAL`. The kernel generator failing is `GSEC_ERR_IO`.
- `gsec_rsa_pkcs1_v15_encrypt` and `gsec_rsa_pkcs1_v15_decrypt` are RSAES-PKCS1-v1_5, the encoding TLS 1.2 key transport uses. Decrypt is that same blinded exponentiation, and the padding scan does not branch on the encoded message. `gsec_rsa_oaep_encrypt` and `gsec_rsa_oaep_decrypt` are OAEP. Neither uses the Chinese remainder theorem.
- `gsec_aes_cbc_encrypt` and `gsec_aes_cbc_decrypt` are AES-CBC with no padding. The initialization vector is the caller's. The mode does not authenticate.
- `gsec_des_encrypt` and `gsec_des_decrypt` are single DES. `gsec_des_ede3_encrypt` and `gsec_des_ede3_decrypt` are three-key Triple DES. Each has a CBC form. Both algorithms are broken. Neither is constant-time.
- `gsec_rc4` is RC4 with no drop. It is broken and not constant-time.
- `gsec_scrypt`, `gsec_bcrypt`, and `gsec_argon2` hash a password for storage. The salt is the caller's. bcrypt rejects a password longer than 72 bytes. Argon2 is version 0x13, and BLAKE2b stays inside it.
- `gsec_ecdsa_p384_public`, `gsec_ecdsa_p384_sign`, and `gsec_ecdsa_p384_verify` are ECDSA on P-384. Coordinates and each half of a signature are 48 bytes. Signing uses SHA-384 and RFC 6979 and emits the low s. Verification accepts a high s.
- `gsec_der_tlv` reads one strict DER value. An indefinite length, a non-minimal integer, and a SET that is not strictly ascending are rejected.
- `gsec_pem_decode` reads the first PEM block. `gsec_pem_encode` writes one.
- `gsec_pkcs8_parse` reads an unencrypted PKCS#8 key: RSA, P-256, P-384, or Ed25519. `gsec_pkcs8_decrypt` opens a PBES2 EncryptedPrivateKeyInfo (PBKDF2 and AES-CBC or three-key Triple DES) and the password bytes are used as given. A wrong password is `GSEC_ERR_MISMATCH` and the buffer is wiped. The pointers address the caller's buffer.
- `gsec_pkcs12_open` reads a PFX. The MAC uses the PKCS#12 key derivation on the password as UTF-16BE with two trailing zero bytes. A PBES2 bag uses the UTF-8 password. The key and the certificates are views of the caller's scratch buffer. RC2 is rejected.
- `gsec_x509_parse` reads one certificate. `gsec_x509_signed_by` checks the signature. `gsec_x509_path` walks a chain the caller arranged, leaf then intermediates then anchor, at a Unix second the caller supplies. `gsec_x509_hostname` matches a DNS name. The path does not check revocation. `gsec_x509_issue` builds a certificate and signs it. A critical extension this parser does not know is rejected.
- `gsec_crl_parse` reads a certificate revocation list. `gsec_crl_signed_by` checks the signature. `gsec_crl_contains` reports whether a serial is on the list. Fetching the list stays with the caller.
- `gsec_ocsp_parse` reads a successful basic OCSP response. `gsec_ocsp_signed_by` checks the signature. `gsec_ocsp_status` looks up a certificate from hashes the caller computed. Fetching the response stays with the caller.
- `gsec_selftest` runs the known-answer checks an embedder can call at startup: equal, wipe, a short entropy call, each hash, HMAC, HKDF, PBKDF2, AES, CTR, CBC, GCM, ChaCha20-Poly1305, X25519, Ed25519, P-256 ECDH, ECDSA P-256 and P-384, a 512-bit RSA signature in both paddings, and one DER value. RSA verification's known answer is the vector file.
- `gsec_poison` and `gsec_unpoison` mark secret bytes for the constant-time gate. In a normal build they do nothing.

The primitive set, including what is pending and what is excluded, is
`tools/oracle/primitives.txt`. Declaring a function the registry does not
list as implemented fails the build.

## Before you call it

- A comparison of secret bytes goes through `gsec_equal`. `memcmp` anywhere under `src/` fails `make test`.
- Verification returns `GSEC_ERR_MISMATCH` when the tag, MAC, or signature does not match. It does not return a boolean, and `GSEC_OK` is the only success.
- `gsec_result_string` returns one of a fixed set of static strings. There is no function that prints a key.
- `NULL` for an allocator is cutil's default. `NULL` for limits is the defaults in `gsec_limits_default`, which cap one `gsec_random_bytes` call at 1 MiB.
- A zero length is success and does not read the pointers. A null pointer with a positive length is `GSEC_ERR_INVALID`.
- `gsec_random_bytes` waits for the kernel generator. It does not fall back to a device node or to cutil's Mersenne Twister.

## Examples

```c
#include <ghoti.io/security/security.h>
#include <stdio.h>

int main(void) {
  unsigned char key[32];
  GSEC_Result result = gsec_random_bytes(key, sizeof key, NULL);

  if (result != GSEC_OK) {
    fprintf(stderr, "entropy: %s\n", gsec_result_string(result));
    return 1;
  }
  result = gsec_selftest();
  gsec_wipe(key, sizeof key);
  return result == GSEC_OK ? 0 : 1;
}
```

`examples/equal.c` compares two hex strings from the command line and prints
`equal` or `mismatch`. `examples/selftest.c` runs `gsec_selftest`.

## Dependencies

Found through pkg-config, and the installed `.pc` file names it, so a
program that links `ghoti.io-security-0` links this too.

- [ghoti.io-cutil](https://github.com/Ghoti-io/cutil) — the allocator.

## Documentation

[documentation/design.md](documentation/design.md) is the design of what
has shipped, the gates, and the phases that have not.
[documentation/oracles.md](documentation/oracles.md) is the pinned OpenSSL and
Wycheproof image. `make test` does not need it. `make check-oracle` fails if
the image is absent. `make docs` builds the manual.

## Status

Phases 0 through 13 are built: the gate, the hashes, HMAC, HKDF, PBKDF2,
AES, CTR, CBC, GCM, ChaCha20-Poly1305, X25519, Ed25519, P-256 ECDH, ECDSA
P-256 and P-384, RSA verification and signing, DES, RC4, scrypt, bcrypt,
Argon2, and the certificate encodings. `make test` runs the unit tests, the symbol, aliasing,
stamp, secret, foundation, and constant-time gates. `make check-oracle` is
separate, because it needs the container. It compares the implemented
primitives with pinned OpenSSL 3.5.7 and with the Wycheproof files named in
[documentation/oracles.md](documentation/oracles.md).

## License

LGPL-3.0-only. See [COPYING.LESSER](COPYING.LESSER) for the license, and
[COPYING](COPYING) for the GPL text it is written as additional permissions
on top of.

Contributions are not being accepted at this time; see
[CONTRIBUTING.md](CONTRIBUTING.md) for what is useful instead.
