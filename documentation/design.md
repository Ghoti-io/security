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
and wiped. No signature is implemented. The primitive
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
| A function that does not exist yet cannot be declared quietly | `check-foundation` reads the registry and the headers. `implemented` must have a declaration. `pending` and `excluded` must not. The check plants `gsec_ed25519` and requires that plant to be rejected while `ed25519` is pending. |
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
| `gsec_selftest` | Runs equal, wipe, a short entropy call, and the RFC 6234 SHA-256 of the empty message and of `abc`. The entropy call folds the output with XOR and then wipes it, and branches on whether any byte was written, which is public. |
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
that does not match the bytes. `equal.vec` and `sha256.vec` are the files.

The container is OpenSSL 3.5.7 and Wycheproof at one commit, built here and
pinned by the base digest, the apt version, and that commit.
`make check-oracle` requires the image. It checks the oracle against NIST's
SHA-256(`abc`) and against the hash of `aes_gcm_test.json` and
`chacha20_poly1305_test.json`, then hashes the
same messages with this library and with `openssl dgst -sha256` in the
image. A digest that differs fails the target.

Fuzz targets `fuzz_equal`, `fuzz_wipe`, and `fuzz_sha256` are libFuzzer
with ASan and UBSan. `fuzz_wipe` traps if a byte of the wiped region is
not zero. `fuzz_sha256` traps if a one-shot digest and a streaming digest
of the same bytes differ.

## 5. Departures from the suite conventions

Recorded in `CONVENTIONS.md` section 13.

- No `GSEC_Stream`. A caller already holds the buffer. Streaming a hash is a design of that hash, not a hole in the skeleton.
- No `_dump` of a secret. The suite's error object can name an offset in a file the caller handed in. A key is not that kind of input, and a working dump would be a disclosure primitive.
- `GSEC_ERR_MISMATCH` is added to the result vocabulary. A tag that does not match is the answer a verifier exists to give. `GSEC_ERR_INVALID` remains "the caller passed a bad argument".

## 6. What this library does not grow

`excluded` in the registry. A declaration is a failed build.

| Id | Why it is absent |
| --- | --- |
| `des`, `rc4` | Broken primitives with no caller. A format that needed MD5 is different: the digest is `gsec_md5`, and the header says it is not a signature, a MAC, or a password hash. |
| `argon2`, `scrypt`, `bcrypt` | Password hashing is a policy and a memory-hard construction. Not a primitive this set needs for TLS or for the archive formats the plan names. |
| `x509`, `pem`, `pkcs8`, `der` | Encoding and policy. They belong in `certificates`. |

`rsa_private` stays `pending` and skippable. Verification has no secret.
Private RSA needs blinding and a constant-time exponentiation, and it is
unnecessary if client keys are Ed25519 or ECDSA. Flipping that row is the
decision to implement it.

`aes_cbc` stays `pending` for 7z, if 7z is ever wanted. It is not part of
the TLS 1.3 set.

## 7. Phases

Each phase's machinery is what the next one is tested with. Archive's set
is complete at phase 3. Certificates need phase 8. TLS needs the rest.
Phase 9 may never be built.

| Phase | What | Why it is here |
| --- | --- | --- |
| 0 | This tree | The gate exists before the thing it gates |
| 1 | SHA-256, SHA-512, SHA-384, SHA-1, and HMAC are implemented | The first algorithms, and they exercise the corpus, the oracle, and `gsec_equal` |
| 2 | HKDF and PBKDF2 are implemented | Small once HMAC exists. HKDF is the high-entropy derivation; PBKDF2 is the slow one, and calling one in place of the other is a different function |
| 3 | AES-128/192/256, CTR, and GCM are implemented | Completes the archive set |
| 4 | ChaCha20-Poly1305 is implemented | TLS 1.3. No bignum |
| 5 | X25519 is implemented | TLS 1.3 key agreement. The all-zero shared secret is rejected |
| 6 | Ed25519 | Needs SHA-512 and that field |
| 7 | P-256: field, point arithmetic, ECDH, ECDSA with RFC 6979 | The first hard one |
| 8 | Bignum, RSA verify (PSS and PKCS#1 v1.5) | Verification only |
| 9 | RSA private operations | Skippable |
| 10 | P-384, if certificates need it | |
| 11 | AES-CBC, if 7z needs it | |

Nonces are the caller's. The GCM and ChaCha20-Poly1305 declarations say what a repeated nonce
does. ECDSA signing uses RFC 6979 so the nonce is a
function of the key and the message. Verification accepts the encodings the
world produces, including a high `s`; signing emits the strict form.

The phase table above is the order. The argument for the set and for the
name stays with the suite's planning notes until the phase it describes
ships, and what has shipped is this file.
