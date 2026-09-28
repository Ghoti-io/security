# Ghoti.io Security

Cryptographic primitives in C. Hashes, message authentication, key
derivation, symmetric encryption, key agreement, signatures, password
hashes, and the kernel generator. Strict DER, PEM, PKCS#8, PKCS#12,
X.509, a certificate revocation list, and a basic OCSP response live
here until a certificates library takes them. Fetching a list or a
response, and reading an operating-system trust store, stay with the
caller. A handshake does not live here.

## Algorithms

This is what the library implements. The Oracle column names the
committed known-answer file and where those bytes came from, and what
`make check-oracle` runs against them. A file the unit tests score is
not, by itself, an outside judge.

### Hashes

| Standard | Oracle | What it means here |
| --- | --- | --- |
| FIPS 180-4 SHA-256 | `sha256.vec` is RFC 6234 §8.1 for the empty string, `abc`, and the two-block message. The padding lengths are digests OpenSSL produced, and OpenSSL 3.5.7 recomputes them. | One-shot and streaming. Final wipes the context. |
| FIPS 180-4 SHA-384 | `sha384.vec` is RFC 6234 §8.3 for those three messages. The padding lengths are OpenSSL's, and OpenSSL 3.5.7 recomputes them. | SHA-512's compression with the FIPS initial value, not a truncated SHA-512 digest. |
| FIPS 180-4 SHA-512 | `sha512.vec` is RFC 6234 §8.4 for those three messages. The padding lengths are OpenSSL's, and OpenSSL 3.5.7 recomputes them. | The same streaming shape. The block is 128 bytes. |
| FIPS 180-4 SHA-1 | `sha1.vec` is RFC 3174 and FIPS 180-4 for the empty string, `abc`, and the two-block message. The padding lengths are OpenSSL's, and OpenSSL 3.5.7 recomputes them. | Does not provide collision resistance. It is here for ZIP and for an old certificate that still has to be hashed so the algorithm can be rejected for that reason. |
| RFC 1321 MD5 | `md5.vec` is RFC 1321 for the six published messages. The padding lengths are OpenSSL's, and OpenSSL 3.5.7 recomputes them. | Little-endian, and not collision resistant. An ICC profile identifier is an MD5, and an old certificate signed with it still has to be hashed. HMAC does not take it. Do not use it for a new signature, a new MAC, or a password. |

### Message authentication and derivation

| Standard | Oracle | What it means here |
| --- | --- | --- |
| FIPS 198-1 / RFC 2104 HMAC | `hmac.vec` is RFC 2104 / RFC 4231 test cases 1 and 6, plus the empty message under the key `key`. OpenSSL 3.5.7 recomputes them. | Over SHA-1, SHA-256, SHA-384, or SHA-512. A key longer than the block is hashed first. `gsec_hmac_verify` compares the MAC with `gsec_equal`. |
| RFC 5869 HKDF | `hkdf.vec` is RFC 5869 appendix A. OpenSSL 3.5.7 recomputes the output. | Extract, then expand, over those same HMACs. A salt of length zero is HashLen zero bytes. An output longer than 255 digests is `GSEC_ERR_LIMIT`. This is the high-entropy derivation. |
| RFC 8018 PBKDF2 | `pbkdf2.vec` is RFC 6070, without the 16,777,216-iteration case. OpenSSL 3.5.7 recomputes the cases that are there. | The same hashes. The iteration count is the cost, and zero is `GSEC_ERR_INVALID`. This is the slow derivation for a password. It is a different function from HKDF. |

### Symmetric ciphers

| Standard | Oracle | What it means here |
| --- | --- | --- |
| FIPS 197 AES-128, AES-192, AES-256 | `aes.vec` is FIPS 197 appendix C, plus further blocks the file records as agreeing with OpenSSL. OpenSSL 3.5.7 recomputes the appendix C blocks and the zero blocks. | One block. The substitution is the field inverse and the affine map. A key byte is not a table index. The schedule from encrypt serves both directions. |
| NIST SP 800-38A CTR | `aes_ctr.vec`. OpenSSL 3.5.7 recomputes the big-endian cases. The little-endian expected values are this library's own AES applied to the counter blocks. OpenSSL implements only the NIST counter, so the WinZip counter has no outside judge. | `GSEC_AES_CTR_BE` is the NIST counter. `GSEC_AES_CTR_LE` is the WinZip counter. |
| NIST SP 800-38A CBC | `aes_cbc.vec` does not cite a published vector. OpenSSL 3.5.7 recomputes the cases. | No padding. The initialization vector is the caller's. The mode does not authenticate. Repeating the vector under one key leaks the equality of plaintext prefixes. |
| NIST SP 800-38D GCM | `aes_gcm.vec` is the NIST all-zero AES-128 vector, plus cases copied from Wycheproof. `make check-oracle` runs the whole pinned `aes_gcm_test.json`. | One shot, at 128, 192, and 256 bits. A 12-byte nonce is the one the standard prefers. Any other positive length is hashed into the initial counter. Decrypt wipes the plaintext when the tag does not match. Nonce reuse under one key destroys authentication. |
| RFC 8439 ChaCha20-Poly1305 | `chacha20_poly1305.vec` is RFC 8439 §2.8.2. `make check-oracle` runs the pinned Wycheproof `chacha20_poly1305_test.json`. | A 32-byte key, a 12-byte nonce, and a 16-byte tag. Decrypt wipes the plaintext when the tag does not match. Nonce reuse under one key destroys authentication. |
| FIPS 46-3 DES, and three-key Triple DES, plus CBC | `des.vec`. The ECB case is the published single-DES example. OpenSSL 3.5.7 recomputes that case, one CBC message, and one three-key block. The file cites no separate source for those two. | Both ciphers are broken. They are here because old formats still name them. The substitution boxes are indexed by key-dependent bits, so neither is constant-time. A wrong parity bit is accepted. CBC does not authenticate, and padding is the caller's. |
| RC4 | `rc4.vec` is a 5-byte key and the plaintext `hello`, written for this library. It is not a published vector, and the oracle does not score it. OpenSSL 3.5.7 is compared on a 16-byte key, because `openssl enc` zero-pads a shorter one. | Broken, and not constant-time. The key is 1 to 256 bytes. There is no drop: the first keystream byte is the first output byte. Do not use it for a new design. |

### Key agreement and signatures

| Standard | Oracle | What it means here |
| --- | --- | --- |
| RFC 7748 X25519 | `x25519.vec` is RFC 7748 §6.1. `make check-oracle` runs the pinned Wycheproof `x25519_test.json`. | A 32-byte scalar and a 32-byte u-coordinate. The scalar is clamped inside the function. A shared secret of all zeros is rejected and the output is wiped. |
| RFC 8032 Ed25519 | `ed25519.vec` is RFC 8032 §7.1, tests 1 and 2. `make check-oracle` runs the pinned Wycheproof `ed25519_test.json`. | Pure Ed25519. No context string and no prehash. The seed and the public key are 32 bytes. The signature is 64. Signing is deterministic. Verification rejects a non-canonical point and an S that is not strictly less than the group order. |
| NIST P-256 ECDH | `ecdh_p256.vec` is one case copied from Wycheproof. `make check-oracle` runs the pinned `ecdh_secp256r1_ecpoint_test.json`. | A 32-byte scalar and a 64-byte point, x then y, with no uncompressed-point prefix. A coordinate that is not strictly less than the prime, a point that is not on the curve, and the point at infinity are rejected and the output is wiped. A shared x of zero is a result. |
| NIST P-384 ECDH | The unit test hardcodes one shared secret taken from OpenSSL, and `make check-oracle` does not recompute it. Wycheproof `ecdh_secp384r1_ecpoint_test.json` is in the pinned image and is not run. | The same contract. A 48-byte scalar and a 96-byte point. TLS 1.2 and TLS 1.3 both name this curve for key agreement. |
| FIPS 186-4 ECDSA P-256, RFC 6979 | `ecdsa_p256.vec` is RFC 6979 appendix A.2.5. `make check-oracle` runs the pinned Wycheproof `ecdsa_secp256r1_sha256_p1363_test.json`. | SHA-256 of the message. The signature is 64 bytes, r then s. Signing emits the low s. Verification accepts a high s. An r or s of zero, or one that is not strictly less than the group order, does not verify. |
| FIPS 186-4 ECDSA P-384, RFC 6979 | `ecdsa_p384.vec` is one RFC 6979 signature, scalar `0x3c` and message `hello`, that the file says OpenSSL 3.5.7 verifies. It is not an appendix case. `make check-oracle` runs the pinned Wycheproof `ecdsa_secp384r1_sha384_p1363_test.json`. | The same contract with SHA-384. Coordinates and each half of a signature are 48 bytes. |
| RFC 8017 RSA | `rsa_pkcs1.vec` is one Wycheproof SHA-256 case, plus MD5 and SHA-1 signatures OpenSSL 3.5.7 produced for `sample`. `rsa_pss.vec` is one Wycheproof SHA-256 case. `make check-oracle` runs the pinned Wycheproof RSASSA-PKCS1-v1_5 and RSASSA-PSS files. | A modulus of at most 4096 bits and an odd public exponent of at least 3. PKCS#1 v1.5 signatures accept only the DER DigestInfo, including the NULL, and at least eight `0xff` bytes. PSS takes the salt length and encodes one bit shorter than the modulus. MD5 and SHA-1 verify so an old certificate can be checked and then rejected for the algorithm. |
| RSA signing | `rsa_private.vec` holds signatures the file says OpenSSL 3.5.7 verifies, for the message `sample`. Those bytes are a snapshot. `make check-oracle` generates a fresh 2048-bit key in the image, this library signs, and OpenSSL verifies. | The private exponent as well as the public one. The exponentiation does not branch on it, and each signature is blinded with a value from the kernel generator. The blinding does not change the signature bytes. The PSS salt is the caller's. A failure wipes the signature. |
| RFC 8017 RSAES-PKCS1-v1_5 | The unit test hardcodes one OpenSSL 3.5.7 ciphertext, and `make check-oracle` does not generate another. Encryption is randomized, so a fixed test has to be a decrypt. The pinned Wycheproof tree has the decrypt schema and no RSAES-PKCS1-v1_5 cases. | The encoding TLS 1.2 key transport uses. Decrypt is the same blinded exponentiation, and the padding scan does not branch on the encoded message. |
| RFC 8017 RSAES-OAEP | The unit test hardcodes one OpenSSL 3.5.7 ciphertext (SHA-256, empty label). The pinned image contains Wycheproof `rsa_oaep_*` files, and `make check-oracle` does not run them. | The hash is the label hash and MGF1. A bad label and bad padding are both `GSEC_ERR_MISMATCH`. Neither encryption uses the Chinese remainder theorem. |

### Password hashes

These store a password. They are not PBKDF2, and none of them is in the
constant-time gate. The salt is the caller's.

| Standard | Oracle | What it means here |
| --- | --- | --- |
| RFC 7914 scrypt | `scrypt.vec` is RFC 7914 §7. OpenSSL 3.5.7 recomputes the NaCl case. | `N` is a power of two, at least 2. The working memory is `128 * r * (N + p)` bytes. More than 32 MiB is `GSEC_ERR_LIMIT` and allocates nothing. |
| bcrypt, the `$2b$` rule | `bcrypt.vec` is the OpenBSD vectors, including the unsigned-byte case. No outside judge. OpenSSL does not implement bcrypt, and no second implementation was added to the image. | A 16-byte salt and a 24-byte ciphertext. A password longer than 72 bytes is `GSEC_ERR_INVALID` rather than truncated. `$2a$` is not implemented. The function does not format a modular-crypt string. The hash is broken for a new system. |
| RFC 9106 Argon2, version `0x13` | `argon2.vec` is RFC 9106 §5.3. No outside judge. OpenSSL 3.5.7 in the image implements Argon2d, Argon2i, and Argon2id, and the comparison was not written. | Argon2d, Argon2i, and Argon2id. Argon2id is the type for password storage. The salt is at least 8 bytes. Lanes are the algorithm's parallelism parameter, and the work runs on the calling thread. BLAKE2b stays inside the hash. |

### Keys and certificates

These stay in this library until a certificates library takes them. A
critical extension the parser does not understand is rejected. The
pointers in a parsed result address the caller's buffer, except an
ECDSA signature, which is copied out so r and s have a fixed width.
The checks are fixtures in the unit tests. `make check-oracle` does
not parse the same bytes with another implementation.

| Standard | Oracle | What it means here |
| --- | --- | --- |
| ITU-T X.690 DER | Fixtures in the unit tests. | One strict value. An indefinite length, a non-minimal length, a tag written in the long form when the short form would do, a non-minimal integer, and a SET that is not strictly ascending are rejected. The reader does not allocate. |
| RFC 7468 PEM | Fixtures in the unit tests. | The first block. Textual headers are not encrypted. A password-encrypted block is still PEM; PKCS#8 decides whether it can read the bytes inside. |
| RFC 5208 / RFC 5958 PKCS#8 | Fixtures in the unit tests. | An unencrypted key: RSA, P-256, P-384, or Ed25519. The caller wipes the buffer the pointers address. |
| RFC 8018 PBES2 | Fixtures in the unit tests. | `gsec_pkcs8_decrypt` opens an EncryptedPrivateKeyInfo with PBKDF2 and AES-CBC or three-key Triple DES. The password bytes are used as given. A wrong password is `GSEC_ERR_MISMATCH` and the buffer is wiped. |
| RFC 7292 PKCS#12 | Fixtures in the unit tests. | A PFX. The MAC turns the UTF-8 password into the BMP string the RFC requires, including the trailing two zero bytes. A PBES2 bag uses the UTF-8 bytes themselves. RC2 is rejected. The key and the certificates are views of the caller's scratch buffer. |
| RFC 5280 X.509 | Fixtures in the unit tests. | One certificate, a signature check, and a path. The caller arranges the chain, leaf then intermediates then anchor, and supplies the Unix second. A DNS name is compared as stored. Internationalized names are the caller's to turn into A-labels. `certificatePolicies` is read and not enforced. The path does not check revocation. |
| X.509 issuance | Fixtures in the unit tests. | `gsec_x509_issue` builds a certificate and signs it with P-256, P-384, Ed25519, or RSA. The output buffer is wiped on failure. |
| RFC 5280 CRL | Fixtures in the unit tests. | Parse, check the signature, and ask whether a serial is on the list. Fetching the list stays with the caller. |
| RFC 6960 OCSP | Fixtures in the unit tests. | A successful basic response. The caller supplies the issuer-name hash and the issuer-key hash. Fetching the response stays with the caller. |

## Before you call it

- A comparison of secret bytes goes through `gsec_equal`. It returns `GSEC_OK` or `GSEC_ERR_MISMATCH`. A wrong tag is a status, not a boolean, and `GSEC_OK` is the only success. `memcmp` anywhere under `src/` fails `make test`.
- `gsec_wipe` overwrites a region through a volatile store, so a later optimisation pass cannot delete the write.
- Verification returns `GSEC_ERR_MISMATCH` when the tag, MAC, or signature does not match.
- `gsec_result_string` returns one of a fixed set of static strings. There is no function that prints a key.
- `NULL` for an allocator is cutil's default. `NULL` for limits is `gsec_limits_default`, which caps one `gsec_random_bytes` call at 1 MiB.
- A zero length is success and does not read the pointers. A null pointer with a positive length is `GSEC_ERR_INVALID`.
- `gsec_random_bytes` waits for the kernel generator: `getrandom` without `GRND_NONBLOCK` on Linux, `getentropy` on macOS, and `BCryptGenRandom` on Windows. A failure wipes what was already written and returns `GSEC_ERR_IO`. There is no userspace generator behind that failure.
- `gsec_random_open` returns a cutil `GCU_Random` whose draws call `gsec_random_bytes` with the default cap. Release it with `gcu_random_free`. A key still goes through `gsec_random_bytes`, which is the call that takes a limit. The handle does not keep unused kernel bytes.
- A nonce is the caller's, except where the algorithm defines it. ECDSA signing uses RFC 6979. Ed25519 signing is deterministic. Reusing a GCM or ChaCha20-Poly1305 nonce under one key destroys authentication.
- `gsec_selftest` runs a known answer for each primitive an embedder can call at startup. It does not print, and it does not return the bytes it used.

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

It prints nothing. A zero exit status is the self-test succeeding.
`examples/equal.c` compares two hex strings and prints `equal` or
`mismatch`. `examples/selftest.c` runs `gsec_selftest`. More programs
under `examples/` exercise one algorithm each.

## Compile and link

Once the library is installed, pkg-config carries the include path, the
library, and its dependency:

```bash
cc -o show show.c $(pkg-config --cflags --libs ghoti.io-security-0)
```

The module name ends in the major version, `-0` for this release, so two
majors can be installed side by side. A build made with `make BRANCH=-dev`
installs `ghoti.io-security-dev` instead.

## Building the library

[cutil](https://github.com/Ghoti-io/cutil) must already be installed
where pkg-config can see it. A dependency it cannot find is a hard error
naming the fix.

```bash
make
make test
sudo make install
```

From the parent of a suite checkout, which installs cutil first:

```bash
./suite/install.sh
export PKG_CONFIG_PATH="$PWD/.local/share/pkgconfig"
make -C libs/security test PREFIX="$PWD/.local"
```

`make test` is the suite: the unit tests, and the symbol, aliasing,
stamp, secret, foundation, and constant-time gates. `make help` lists
the rest.

| Target | What it does |
| --- | --- |
| `make test-asan` | Rebuild with ASan and UBSan and run the suite |
| `make test-valgrind` | Run the suite under Valgrind |
| `make check-ct` | The constant-time gate. Needs memcheck |
| `make check-oracle` | Differentials against pinned OpenSSL and Wycheproof, in a container |
| `make oracle-build` | Build that container |
| `make fuzz` | Build and run the libFuzzer harnesses |
| `make docs` | The Doxygen manual, into `./docs` |

`make test` does not run a container. `make check-oracle` fails if the
image is missing.

## The API

Everything is prefixed `gsec_` / `GSEC_`, under `<ghoti.io/security/...>`.
`<ghoti.io/security/security.h>` is the umbrella.

- **`secret.h`** — `gsec_equal`, `gsec_wipe`, and the marks the constant-time gate reads. In a normal build the marks do nothing.
- **`random.h`** — `gsec_random_bytes` and `gsec_random_open`.
- **`sha256.h`**, **`sha384.h`**, **`sha512.h`**, **`sha1.h`**, **`md5.h`** — one hash each. Each has `init`, `update`, `final`, and a one-shot.
- **`hmac.h`**, **`hkdf.h`**, **`pbkdf2.h`** — MAC and the two derivations.
- **`aes.h`**, **`aes_ctr.h`**, **`aes_cbc.h`**, **`aes_gcm.h`**, **`chacha20_poly1305.h`**, **`des.h`**, **`rc4.h`** — one cipher or mode.
- **`x25519.h`**, **`ed25519.h`**, **`ecdh_p256.h`**, **`ecdh_p384.h`**, **`ecdsa_p256.h`**, **`ecdsa_p384.h`**, **`rsa.h`** — agreement, signatures, and RSA encryption.
- **`scrypt.h`**, **`bcrypt.h`**, **`argon2.h`** — password hashes for storage.
- **`der.h`**, **`pem.h`**, **`pkcs8.h`**, **`pkcs12.h`**, **`x509.h`**, **`crl.h`**, **`ocsp.h`** — the encodings.
- **`selftest.h`** — `gsec_selftest`.
- **`allocator.h`** — `GSEC_Allocator`, which is cutil's `GCU_Allocator`.
- **`core.h`** — the result codes and `GSEC_Limits`.

[Algorithms](#algorithms) is what is implemented.
[Before you call it](#before-you-call-it) is what that changes about a call.

## Dependencies

Found through pkg-config, and the installed `.pc` file names it, so a
program that links `ghoti.io-security-0` links this too.

- [ghoti.io-cutil](https://github.com/Ghoti-io/cutil) — the allocator.
  `random.h` includes cutil's `random.h`, so a caller of `gsec_random_open`
  gets the `GCU_Random` type.

## Documentation

| Page | What it settles |
| --- | --- |
| [documentation/design.md](documentation/design.md) | What a call has to guarantee, and how the gates enforce it |
| [documentation/oracles.md](documentation/oracles.md) | The pinned OpenSSL 3.5.7 and Wycheproof image, and which primitive each file judges |

`make docs` builds the manual from the headers.

## Status

The algorithms in the tables above are implemented. The Oracle column
says which known-answer file each one scores, and which outside program
recomputes it. The Windows `BCryptGenRandom` path is written and has
not been compiled.

## License

LGPL-3.0-only. See [COPYING.LESSER](COPYING.LESSER) for the license, and
[COPYING](COPYING) for the GPL text it is written as additional permissions
on top of.

Contributions are not being accepted at this time; see
[CONTRIBUTING.md](CONTRIBUTING.md) for what is useful instead.
