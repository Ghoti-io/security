# Design

Phase 0 is implemented (2026-09-26): the skeleton, the constant-time gate,
the vector corpus, constant-time compare, and the entropy and explicit-zero
calls. SHA-256, SHA-512, SHA-384, SHA-1, MD5, HMAC over the SHA
hashes, and HKDF and PBKDF2 are implemented. MD5 does not provide collision
resistance; the declaration says so, and HMAC does not take it. HKDF is the high-entropy derivation and
PBKDF2 is the slow one; they are different functions. AES-128, AES-192, and
AES-256 encrypt and decrypt one block; the substitution is table-free. CTR
increments the counter big-endian, as NIST specifies, or little-endian, as
WinZip does. GCM is one shot. ChaCha20-Poly1305 is one shot, with a fixed
32-byte key, 12-byte nonce, and 16-byte tag. A tag that does not match wipes the plaintext.
Nonce reuse under one key destroys authentication, and both declarations say so.
X25519 is RFC 7748. The scalar is clamped inside the function, and the top
bit of the u-coordinate is ignored. A shared secret of all zeros is rejected
and wiped. Ed25519 is RFC 8032, pure, with no context string. Signing is
deterministic. Verification rejects a non-canonical point and an S that is
not strictly less than the group order. P-256 ECDH uses the complete
addition formula. A coordinate that is not strictly less than the prime,
a point that is not on the curve, and the point at infinity are rejected
and the output is wiped. A shared x of zero is a result, not a failure.
ECDSA P-256 hashes the message with SHA-256 and derives the nonce with
RFC 6979. Signing emits the low s. Verification accepts a high s. An r or
s of zero, or one that is not strictly less than the group order, does
not verify. RSA verification is the public exponent only. PKCS#1 v1.5
accepts the DER DigestInfo, including the NULL, and at least eight 0xff
bytes. PSS takes the salt length from the caller and encodes one bit
shorter than the modulus. MD5 and SHA-1 verify so an old certificate
can be checked and then rejected for the algorithm. Signing takes the
private exponent as well. The exponentiation does not branch on it, and
each signature is blinded with a value from the kernel generator. The
blinding does not change the signature bytes. The PSS salt is the
caller's.
A modulus past 4096 bits is rejected. The primitive
registry in `tools/oracle/primitives.txt` is the list of what may be
declared. The phases below are the order the rest is built in.

`security` is the suite's cryptographic primitives library. Certificates,
DER, a handshake, a key file, and a trust store are other libraries. The
name is broader than the scope, and the first paragraph of the README is
where that is said to a caller. The prefix is `GSEC_` / `gsec_`. The
package is `ghoti.io-security-0`, the include path
`<ghoti.io/security/...>`. It depends on `cutil` and on nothing else.

---

## 1. What has to be true of a call

| Property | How it is enforced |
| --- | --- |
| A wrong tag is a failure | `gsec_equal` returns `GSEC_ERR_MISMATCH`. Verification does not return a boolean. `GSEC_OK` is zero and is the only success. |
| Secret bytes are not compared with `memcmp` | `tools/check-secret.py` scans `src/`, including comments, and rejects `memcmp`, `bcmp`, `timingsafe_bcmp`, cutil's Mersenne Twister, a userspace device node, `RAND_bytes`, and the `printf` family. The scanner is run against a plant of its own, so a pattern that stops matching fails the build. |
| A branch on a secret is visible | `make check-ct` builds the library with `-DGSEC_CT_TEST` at the same `-O2` as the release objects. `tools/ct/clean` compares equal buffers and must be silent under memcheck. `tools/ct/leak` branches on a secret byte and must be reported. Both refuse to run unless memcheck is the caller. A clean leak, or a dirty `gsec_equal`, fails `make test`. |
| Entropy comes from the kernel | `gsec_random_bytes` calls `getrandom` without `GRND_NONBLOCK` on Linux, `getentropy` on macOS, and `BCryptGenRandom` on Windows. A short read is retried. Any other failure wipes the output and returns `GSEC_ERR_IO`. |
| A wiped buffer stays wiped | `gsec_wipe` writes through a `volatile` pointer. The compiler is not trusted to keep a `memset` of a dead buffer. |
| Nothing in the library prints a secret | `gsec_result_string` returns one of a fixed table of static strings. There is no `_dump` for a key, a scalar, or a derived secret. |
| A function that does not exist yet cannot be declared quietly | `check-foundation` reads the registry and the headers. `implemented` must have a declaration. `pending` and `excluded` must not. The check plants `gsec_ecdsa_p384` and requires that plant to be rejected while `ecdsa_p384` is pending. |
| An outside judge, once the function exists | An `implemented` row whose judge is not `self` requires a vector file hashed in `tests/data/vectors/MANIFEST`. The container image is how that judge is run. See [oracles.md](oracles.md). |

`GSEC_Limits` has one field, `max_random_bytes`, default 1 MiB, because that
is the only call phase 0 can be asked to run without a bound the caller
already paid for. A field nothing checks is not a promise. Later primitives
add their fields in the commit that enforces them.

A zero length is success and does not read the pointers. A null pointer
with a positive length is `GSEC_ERR_INVALID`, before any load.

No allocation in this library may depend on a secret: not its size, and not
whether it happens. memcheck will not report that. It is a rule for the
phases that allocate.

## 2. What is implemented

| Function | Contract |
| --- | --- |
| `gsec_equal` | Compare `n` bytes. `GSEC_OK` or `GSEC_ERR_MISMATCH`. The loop is volatile. Under `GSEC_CT_TEST` the accumulator is marked defined before the branch on it, so the branch memcheck sees is on a public result. |
| `gsec_wipe` | Overwrite `n` bytes. Returns a result so a null pointer with a positive length is `GSEC_ERR_INVALID` rather than a crash. |
| `gsec_poison`, `gsec_unpoison` | Valgrind client requests when `GSEC_CT_TEST` is set, otherwise empty. They return void: marking is not a result the caller branches on. |
| `gsec_random_bytes` | Fill `out` with `n` bytes from the kernel, or leave it wiped and return an error. `n` above `max_random_bytes` is `GSEC_ERR_LIMIT` and does not write. |
| `gsec_sha256_init`, `gsec_sha256_update`, `gsec_sha256_final`, `gsec_sha256` | FIPS 180-4 SHA-256. The message length is public. Message bytes are not a branch condition and not a table index. Final wipes the context. A bit length that does not fit in 64 bits wipes it and returns `GSEC_ERR_LIMIT`. |
| `gsec_selftest` | A known answer for each implemented primitive except RSA verification, whose known answer is the vector file. Signing's known answer is a 512-bit key. The entropy call folds the output with XOR and then wipes it, and branches on whether any byte was written, which is public. |
| `gsec_sha512`, `gsec_sha384`, `gsec_sha1`, `gsec_md5` | The same shape as SHA-256. SHA-384 is SHA-512's compression with the FIPS 180-4 initial value. SHA-1 and MD5 do not provide collision resistance. MD5 is not a MAC. |
| `gsec_hmac`, `gsec_hmac_verify` | HMAC over SHA-256, SHA-512, SHA-384, or SHA-1. A key longer than the block is hashed first. Verify returns `GSEC_ERR_MISMATCH` when a tag of the digest length differs, and `GSEC_ERR_INVALID` when the length is wrong. |
| `gsec_hkdf` | HKDF: extract, then expand. A salt of length zero is HashLen zero bytes. An output longer than 255 digests is `GSEC_ERR_LIMIT`. |
| `gsec_pbkdf2` | PBKDF2. Zero iterations are `GSEC_ERR_INVALID`. A different function from `gsec_hkdf`. |
| `gsec_aes_encrypt`, `gsec_aes_decrypt` | One AES block at 128, 192, or 256 bits. The schedule from encrypt init serves both directions. A key byte is not a table index. |
| `gsec_aes_ctr` | That block cipher in CTR. `GSEC_AES_CTR_BE` is the NIST counter. `GSEC_AES_CTR_LE` is the WinZip counter. |
| `gsec_aes_gcm_encrypt`, `gsec_aes_gcm_decrypt` | AES-GCM, one shot. Decrypt wipes the plaintext when the tag does not match. Nonce reuse under one key destroys authentication. |
| `gsec_chacha20_poly1305_encrypt`, `gsec_chacha20_poly1305_decrypt` | AEAD_CHACHA20_POLY1305. The key is 32 bytes, the nonce 12, the tag 16. Decrypt wipes the plaintext when the tag does not match. |
| `gsec_x25519`, `gsec_x25519_public` | RFC 7748. The scalar is clamped inside the function. The all-zero shared secret is rejected and the output is wiped. |
| `gsec_ed25519_public`, `gsec_ed25519_sign`, `gsec_ed25519_verify` | RFC 8032, pure, with no context string. Verification rejects a non-canonical point and an S that is not strictly less than the group order. |
| `gsec_ecdh_p256`, `gsec_ecdh_p256_public` | A 32-byte scalar and a 64-byte point, x then y. A non-canonical coordinate, an off-curve point, and infinity are rejected and the output is wiped. A shared x of zero is a result. |
| `gsec_ecdsa_p256_public`, `gsec_ecdsa_p256_sign`, `gsec_ecdsa_p256_verify` | SHA-256 of the message and an RFC 6979 nonce. The signature is 64 bytes, r then s. Signing emits the low s. Verification accepts a high s. An r or s of zero, or one that is not strictly less than the group order, is `GSEC_ERR_MISMATCH`. |
| `gsec_rsa_pkcs1_v15_verify`, `gsec_rsa_pss_verify` | The public exponent. PKCS#1 v1.5 accepts the DER DigestInfo, including the NULL, and at least eight 0xff bytes. PSS takes the salt length and encodes one bit shorter than the modulus. A modulus past 4096 bits is `GSEC_ERR_LIMIT`. |
| `gsec_rsa_private_pkcs1_v15_sign`, `gsec_rsa_private_pss_sign` | The same encodings, raised to the private exponent. The exponentiation does not branch on that exponent. The base is blinded with a value from the kernel generator, and the signature bytes are still the unblinded result. The PSS salt is the caller's. A failure wipes the signature. |
| `gsec_allocator_default` | cutil's default allocator. |
| `gsec_limits_default` | Fills the default caps. NULL is ignored. |
| `gsec_result_string` | Static string, including for a value outside the enum. |
| `gsec_version_string`, `gsec_version_number` | The version the Makefile generated. Packed as `(major << 16) \| (minor << 8) \| patch`. |

The public umbrella is `security.h`.

## 3. Entropy and wipe live here for now

The plan assigns the syscall and the explicit zero to `cutil`, with this
library owning the contract: fail closed, no userspace generator, wipe on
failure. `cutil` has neither. `gcu_random_mt` is a Mersenne Twister, and
`memory.h` counts allocations. Both calls are implemented here so the
contract is tested, and `check-secret` rejects a use of the Twister under
`src/`.

When `cutil` grows `gcu_random_bytes` and an explicit zero with this
contract, these two functions become wrappers and the syscall leaves this
tree. Until that commit, a caller who needs the contract uses these.

The Windows branch calls `BCryptGenRandom` with
`BCRYPT_USE_SYSTEM_PREFERRED_RNG` and links `bcrypt`. It has not been
compiled or run. The marker is `TODO(windows)` in `src/random/random.c` and
in the Makefile, and the check list is `notes/suite/WINDOWS-TODO.md`.

## 4. The corpus and the oracle

Known-answer files under `tests/data/vectors/` are scored by the unit tests
with no container. `MANIFEST` is their SHA-256. The parser fails closed on
truncation, odd hex, uppercase digits, a boolean expectation, and a length
that does not match the bytes. Each implemented primitive with an outside
judge has a file, named on its registry row.

The container is OpenSSL 3.5.7 and Wycheproof at one commit, built here and
pinned by the base digest, the apt version, and that commit.
`make check-oracle` requires the image. What it compares, and which
Wycheproof file judges which primitive, is [oracles.md](oracles.md). A
difference fails the target.

The fuzz targets under `tests/fuzz/` are libFuzzer with ASan and UBSan,
one for each implemented algorithm, plus equal and wipe. `fuzz_wipe`
traps if a byte of the wiped region is not zero. `fuzz_sha256` traps if a
one-shot digest and a streaming digest of the same bytes differ. `make test`
does not run the fuzzers.

## 5. Departures from the suite conventions

Recorded in `CONVENTIONS.md` section 13.

- No `GSEC_Stream`. A caller already holds the buffer. Streaming a hash is a design of that hash, not a hole in the skeleton.
- No `_dump` of a secret. The suite's error object can name an offset in a file the caller handed in. A key is not that kind of input, and a working dump would be a disclosure primitive.
- `GSEC_ERR_MISMATCH` is added to the result vocabulary. A tag that does not match is the answer a verifier exists to give. `GSEC_ERR_INVALID` remains "the caller passed a bad argument".

## 6. What this library does not grow

`excluded` in the registry. A declaration is a failed build.

| Id | Why it is absent |
| --- | --- |
| `x509`, `pem`, `pkcs8`, `der` | Encoding and policy. They belong in `certificates`. |

`des`, `rc4`, `argon2`, `scrypt`, and `bcrypt` are `pending`. DES and RC4
are broken, and old formats still use them. Argon2, scrypt, and bcrypt are
password hashes for storage. PBKDF2 is the slow derivation a format names;
it is not one of those three. Declaring any of them before its row says
`implemented` fails the build.

## 7. Phases

Each phase's machinery is what the next one is tested with. Archive's set
is complete at phase 3. Certificates need phase 8. A TLS server that holds
an RSA key, and a client certificate whose key is RSA, need phase 9.

| Phase | What | Why it is here |
| --- | --- | --- |
| 0 | This tree | The gate exists before the thing it gates |
| 1 | SHA-256, SHA-512, SHA-384, SHA-1, and HMAC are implemented | The first algorithms, and they exercise the corpus, the oracle, and `gsec_equal` |
| 2 | HKDF and PBKDF2 are implemented | Small once HMAC exists. HKDF is the high-entropy derivation; PBKDF2 is the slow one, and calling one in place of the other is a different function |
| 3 | AES-128/192/256, CTR, and GCM are implemented | Completes the archive set |
| 4 | ChaCha20-Poly1305 is implemented | TLS 1.3. No bignum |
| 5 | X25519 is implemented | TLS 1.3 key agreement. The all-zero shared secret is rejected |
| 6 | Ed25519 is implemented | RFC 8032. Verification rejects a non-canonical point and a non-canonical S |
| 7 | P-256 ECDH and ECDSA are implemented | ECDH rejects a non-canonical coordinate, an off-curve point, and infinity. ECDSA signs with RFC 6979, emits the low s, and accepts a high s |
| 8 | RSA-PSS and PKCS#1 v1.5 verification are implemented | Public exponent only. The DigestInfo is the DER encoding, including the NULL. A modulus past 4096 bits is rejected |
| 9 | RSA private signing is implemented | The exponentiation does not branch on the private exponent. The base is blinded. PKCS#1 v1.5 and PSS both sign. The PSS salt is the caller's. A modulus past 4096 bits is rejected |
| 10 | P-384, if certificates need it | |
| 11 | AES-CBC is implemented | No padding. The initialization vector is the caller's. The mode does not authenticate. A repeated vector under one key leaks prefix equality |
| 12 | DES and RC4 | Broken, and old formats still use them |
| 13 | Argon2, scrypt, and bcrypt | Password hashes for storage. Not PBKDF2 |

Nonces are the caller's. The GCM and ChaCha20-Poly1305 declarations say what a repeated nonce
does. ECDSA signing uses RFC 6979 so the nonce is a
function of the key and the message. Verification accepts the encodings the
world produces, including a high `s`; signing emits the strict form.

The phase table above is the order. The argument for the set and for the
name stays with the suite's planning notes until the phase it describes
ships, and what has shipped is this file.
