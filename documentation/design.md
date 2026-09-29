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
and wiped. Ed25519 is RFC 8032. Pure signing uses an empty domain
string. Ed25519ctx binds a context of at most 255 bytes. Ed25519ph signs
SHA-512 of the message. Signing is deterministic. Verification rejects a non-canonical point and an S that is
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
declared, and it now holds no `pending` row. The phases in section 7 are
the order this was built in, and every one of them is implemented; section
2 is the contract each call carries.

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
| The exploit mitigations are on | `check-harden` requires the probe to reject a flag that does not exist, to have accepted at least one that does, and - on Linux - requires the built library to reference the stack protector and to be linked `BIND_NOW`. Flags probed away silently are the failure this catches. |
| A wiped buffer stays wiped | `gsec_wipe` writes through a `volatile` pointer. The compiler is not trusted to keep a `memset` of a dead buffer. |
| Nothing in the library prints a secret | `gsec_result_string` returns one of a fixed table of static strings. There is no `_dump` for a key, a scalar, or a derived secret. |
| A function that does not exist yet cannot be declared quietly | `check-foundation` reads the registry and the headers. `implemented` must have a declaration. `pending` and `excluded` must not. The check plants `gsec_x448` and requires that plant to be rejected, because `x448` is excluded. |
| An outside judge, once the function exists | An `implemented` row whose judge is not `self` requires a vector file hashed in `tests/data/vectors/MANIFEST`, and the oracle probe's coverage set must be exactly the rows whose judge is not `self` or `none`, so a primitive cannot land without a comparison. The container image is how that judge is run. See [oracles.md](oracles.md). |

`GSEC_Limits` has one field, `max_random_bytes`, default 1 MiB, because that
is the only call phase 0 can be asked to run without a bound the caller
already paid for. A field nothing checks is not a promise. Later primitives
add their fields in the commit that enforces them.

A zero length is success and does not read the pointers. A null pointer
with a positive length is `GSEC_ERR_INVALID`, before any load.

No allocation in this library may depend on a secret: not its size, and not
whether it happens. memcheck will not report that. It is a rule for the
phases that allocate.

### The stack an embedder has to have

Everything but `scrypt` and `argon2` works in automatic storage, so the
cost is stack rather than heap, and the RSA private path is the deep one.
Measured with `-fstack-usage` at `-O2`: `bn_modinv_ct` 9,200 bytes in one
frame, `rsa_blinded` 4,896, `gsec_rsa_private_pss_sign` 4,048,
`gsec_rsa_oaep_mgf_decrypt` 3,376, `gsec_x509_path` 5,712. The deepest
chain is a private-key operation at roughly **18 KB**, plus what
`mont_mul` adds under it.

A thread with an 8 or 16 KB stack cannot sign. That is a real
configuration - a small embedded RTOS task, or a deliberately small
pthread stack - so the number is recorded here rather than left to be
discovered. The build carries `-fstack-clash-protection` and
`-fstack-protector-strong` where the compiler has them
(`check-harden` asserts they survived the probe), so an overflow is a
crash rather than a silent corruption.

## 2. What is implemented

| Function | Contract |
| --- | --- |
| `gsec_equal` | Compare `n` bytes. `GSEC_OK` or `GSEC_ERR_MISMATCH`. The loop is volatile. Under `GSEC_CT_TEST` the accumulator is marked defined before the branch on it, so the branch memcheck sees is on a public result. |
| `gsec_wipe` | Overwrite `n` bytes. Returns a result so a null pointer with a positive length is `GSEC_ERR_INVALID` rather than a crash. |
| `gsec_poison`, `gsec_unpoison` | Valgrind client requests when `GSEC_CT_TEST` is set, otherwise empty. They return void: marking is not a result the caller branches on. |
| `gsec_random_bytes` | Fill `out` with `n` bytes from the kernel, or leave it wiped and return an error. `n` above `max_random_bytes` is `GSEC_ERR_LIMIT` and does not write. |
| `gsec_random_open` | A `GCU_Random` over that call, with the default cap and no leftover kernel bytes. `NULL` if the handle cannot be allocated. A draw fails when the kernel call fails, and that draw's output is wiped. Release it with `gcu_random_free`. A key still uses `gsec_random_bytes`, which is the call that takes a `GSEC_Limits`. |
| `gsec_sha256_init`, `gsec_sha256_update`, `gsec_sha256_final`, `gsec_sha256` | FIPS 180-4 SHA-256. The message length is public. Message bytes are not a branch condition and not a table index. Final wipes the context. A bit length that does not fit in 64 bits wipes it and returns `GSEC_ERR_LIMIT`. |
| `gsec_selftest` | A known answer for each implemented primitive except RSA verification, whose known answer is the vector file. Signing's known answer is a 512-bit key. The entropy call folds the output with XOR and then wipes it, and branches on whether any byte was written, which is public. |
| `gsec_sha512`, `gsec_sha384`, `gsec_sha1`, `gsec_md5` | The same shape as SHA-256. SHA-384 is SHA-512's compression with the FIPS 180-4 initial value. SHA-1 and MD5 do not provide collision resistance. MD5 is not a MAC. |
| `gsec_hmac`, `gsec_hmac_verify` | HMAC over SHA-256, SHA-512, SHA-384, or SHA-1. A key longer than the block is hashed first. Verify returns `GSEC_ERR_MISMATCH` when a tag of the digest length differs, and `GSEC_ERR_INVALID` when the length is wrong. |
| `gsec_hkdf` | HKDF: extract, then expand. A salt of length zero is HashLen zero bytes. An output longer than 255 digests is `GSEC_ERR_LIMIT`. |
| `gsec_pbkdf2` | PBKDF2. Zero iterations are `GSEC_ERR_INVALID`. A different function from `gsec_hkdf`. |
| `gsec_aes_encrypt`, `gsec_aes_decrypt` | One AES block at 128, 192, or 256 bits. The schedule from encrypt init serves both directions. A key byte is not a table index. |
| `gsec_aes_ctr` | That block cipher in CTR. `GSEC_AES_CTR_BE` is the NIST counter. `GSEC_AES_CTR_LE` is the WinZip counter. |
| `gsec_aes_gcm_encrypt`, `gsec_aes_gcm_decrypt` | AES-GCM, one shot. Decrypt wipes the plaintext when the tag does not match. Nonce reuse under one key destroys authentication. |
| `gsec_aes_cbc_encrypt`, `gsec_aes_cbc_decrypt` | AES-CBC. No padding, so the length is a multiple of the block, and the initialization vector is the caller's. The mode does not authenticate, and a repeated vector under one key leaks prefix equality. |
| `gsec_chacha20_poly1305_encrypt`, `gsec_chacha20_poly1305_decrypt` | AEAD_CHACHA20_POLY1305. The key is 32 bytes, the nonce 12, the tag 16. Decrypt wipes the plaintext when the tag does not match. |
| `gsec_des_encrypt`, `gsec_des_decrypt`, and the EDE2, EDE3, and CBC forms | DES, two-key Triple DES, and three-key Triple DES, with no padding. All are broken, and none is constant-time. They are here because an old archive, PKCS#12, and PBES1 name them. |
| `gsec_rc2_encrypt`, `gsec_rc2_decrypt`, `gsec_rc2_cbc_encrypt`, `gsec_rc2_cbc_decrypt` | RC2, RFC 2268, with the effective key length in bits as its own parameter. Broken, and not constant-time: the key expansion indexes a substitution table with key bytes. It is here because PKCS#12 and PBES1 name it. |
| `gsec_rc4` | RC4. One call either way, since the operation is its own inverse. `out` may be `in`, and a partial overlap is `GSEC_ERR_INVALID`. Broken, and not constant-time. |
| `gsec_x25519`, `gsec_x25519_public` | RFC 7748. The scalar is clamped inside the function. The all-zero shared secret is rejected and the output is wiped. |
| `gsec_ed25519_public`, `gsec_ed25519_sign`, `gsec_ed25519_verify`, `gsec_ed25519_ctx_sign`, `gsec_ed25519_ctx_verify`, `gsec_ed25519_ph_sign`, `gsec_ed25519_ph_verify` | RFC 8032. Signing is pure with an empty domain string; the `ctx` pair binds a context of at most 255 bytes, and the `ph` pair signs SHA-512 of the message. Verification rejects a non-canonical point and an S that is not strictly less than the group order. |
| `gsec_ecdh_p256`, `gsec_ecdh_p256_public` | A 32-byte scalar and a 64-byte point, x then y. A non-canonical coordinate, an off-curve point, and infinity are rejected and the output is wiped. A shared x of zero is a result. |
| `gsec_ecdh_p384`, `gsec_ecdh_p384_public` | The same contract on P-384: a 48-byte scalar and a 96-byte point. TLS 1.2 and TLS 1.3 both name this curve for key agreement. |
| `gsec_ecdsa_p256_public`, `gsec_ecdsa_p256_sign`, `gsec_ecdsa_p256_verify` | SHA-256 of the message and an RFC 6979 nonce. The signature is 64 bytes, r then s. Signing emits the low s. Verification accepts a high s. An r or s of zero, or one that is not strictly less than the group order, is `GSEC_ERR_MISMATCH`. |
| `gsec_ecdsa_p384_public`, `gsec_ecdsa_p384_sign`, `gsec_ecdsa_p384_verify` | The same contract on P-384: SHA-384 of the message, an RFC 6979 nonce, and a 96-byte signature, r then s. |
| `gsec_rsa_pkcs1_v15_verify`, `gsec_rsa_pss_verify` | The public exponent. PKCS#1 v1.5 accepts the DER DigestInfo, including the NULL, and at least eight 0xff bytes. PSS takes the salt length and encodes one bit shorter than the modulus. A modulus past 4096 bits is `GSEC_ERR_LIMIT`. |
| `gsec_rsa_private_pkcs1_v15_sign`, `gsec_rsa_private_pss_sign` | The same encodings, raised to the private exponent. The exponentiation does not branch on that exponent. The base is blinded with a value from the kernel generator, and the signature bytes are still the unblinded result. The PSS salt is the caller's. A failure wipes the signature. |
| `gsec_rsa_pkcs1_v15_encrypt`, `gsec_rsa_pkcs1_v15_decrypt` | RSAES-PKCS1-v1_5. Decrypt is the blinded private operation. The padding scan does not branch on the encoded message. This is the TLS 1.2 RSA key-transport primitive. |
| `gsec_rsa_oaep_encrypt`, `gsec_rsa_oaep_decrypt` | RSAES-OAEP. The hash is the label hash and MGF1. A bad label and bad padding are both `GSEC_ERR_MISMATCH`. |
| `gsec_scrypt` | RFC 7914. N is a power of two and at least 2; the working set is 128*r*(N+p) bytes, and more than `GSEC_SCRYPT_MEMORY_MAX` is `GSEC_ERR_LIMIT` and allocates nothing. ROMix reads memory at an index derived from the password, so this is not in the constant-time gate. |
| `gsec_bcrypt`, `gsec_bcrypt_2a`, `gsec_bcrypt_2x` | `$2b$`, which is also `$2y$`; the other two check a `$2a$` and a `$2x$` hash. The salt is the caller's 16 bytes and the cost is log2 of the round count. A password past 72 bytes is `GSEC_ERR_INVALID` rather than silently truncated. The output is the 24-byte ciphertext, not a modular-crypt string. The key schedule indexes from the password, so this is not in the gate. |
| `gsec_argon2`, `gsec_argon2_version`, `gsec_argon2_phc`, `gsec_argon2_phc_verify` | RFC 9106 at version 0x13, with Argon2id the type for a new store. `gsec_argon2_version` also takes 0x10 to check an old hash, and a PHC string with no version is read as that version. The salt is at least 8 bytes, and the cost parameters are public. Argon2d, and Argon2id after the first half of the first pass, index from the password, so none of the three is in the gate. |
| `gsec_der_tlv` | One DER value, viewed inside the caller's buffer, with no allocation. An indefinite length, a non-minimal length or tag, and a truncated value are `GSEC_ERR_CORRUPT`. Bytes after the value are not an error; the caller advances by `total_len`. |
| `gsec_pem_decode`, `gsec_pem_encode` | The first PEM block in, and one block out at 64 characters to the line. Neither output is NUL-terminated, and the decoded bytes are not a string. |
| `gsec_pkcs8_parse`, `gsec_pkcs8_decrypt` | An unencrypted PrivateKeyInfo, and an EncryptedPrivateKeyInfo under PBES2 or PBES1. The result is the RSA factors or the elliptic scalar. An Ed25519 seed is the raw 32 bytes or one octet string around them, which is what OpenSSL and RFC 8410 write. The password bytes are used as given. |
| `gsec_pkcs12_open` | A PFX, RFC 7292. The MAC turns the UTF-8 password into the BMP string with the trailing two zero bytes; a PBES2 or PBES1 bag uses the UTF-8 bytes themselves. A wrong password fails the MAC. The key and the certificates are views of the caller's scratch buffer, or of the input where a bag was not encrypted. |
| `gsec_x509_parse`, `gsec_x509_signed_by` | One certificate, viewed in the caller's buffer, and its signature checked with the primitives above. A critical extension this parser does not understand is rejected. certificatePolicies is read and not enforced. |
| `gsec_x509_path`, `gsec_x509_purpose`, `gsec_x509_hostname` | A chain the caller arranged leaf, intermediates, anchor, at a Unix second, with both ends of each validity period inclusive. It refuses what RFC 5280 does not require a validator to refuse, because the caller of this function is making a trust decision: a link signed with MD5 or SHA-1, an RSA key below `GSEC_X509_RSA_MIN_BITS`, and an anchor outside its own dates - section 6.1 treats the anchor as trusted input, and an expired root is a thing that happens. `purpose`, when it is not 0, is one `GSEC_X509_EKU_*` bit the leaf's extendedKeyUsage must permit; `gsec_x509_purpose` is the same test for a caller that would rather apply it itself. A certificate with no extendedKeyUsage permits everything, one naming anyExtendedKeyUsage permits everything, and one naming only purposes this parser has no bit for permits nothing. An anchor with no basicConstraints is trusted as a CA, and one that says it is not a CA is rejected. Name constraints on dNSName and directoryName are applied and any other type is `GSEC_ERR_UNSUPPORTED`. The path does not check revocation. A wildcard is only the entire leftmost label. |
| `gsec_x509_issue` | A certificate built and signed with P-256, P-384, Ed25519, or RSA. The result parses with `gsec_x509_parse`. A failure wipes the output. |
| `gsec_crl_parse`, `gsec_crl_signed_by`, `gsec_crl_contains` | A revocation list, its signature, and a serial lookup where a hit is `GSEC_OK` and an absent serial is `GSEC_ERR_MISMATCH`. Fetching the list stays with the caller. |
| `gsec_ocsp_parse`, `gsec_ocsp_signed_by`, `gsec_ocsp_status` | A basic response, RFC 6960. The caller supplies the issuer-name and issuer-key hashes; a CertID that is not in the response is `GSEC_ERR_MISMATCH`. Fetching the response stays with the caller. |
| `gsec_allocator_default` | cutil's default allocator. |
| `gsec_limits_default` | Fills the default caps. NULL is ignored. |
| `gsec_result_string` | Static string, including for a value outside the enum. |
| `gsec_version_string`, `gsec_version_number` | The version the Makefile generated. Packed as `(major << 16) \| (minor << 8) \| patch`. |

The public umbrella is `security.h`.

## 3. Entropy and wipe stay here

The kernel call and the explicit zero stay in this library. CUtil has the
seeded generators and the handle, and it does not call the kernel.
`gsec_random_open` is the adapter: a `GCU_Random` whose fill function is
`gsec_random_bytes` with the default cap. The handle does not keep unused
kernel bytes. A key is still drawn with `gsec_random_bytes`, which is the
call that takes a `GSEC_Limits`. `check-secret` rejects a use of the
Twister under `src/`.

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

Each harness has one hand-built seed, named `*.seed` and derived from the
vectors and the certificate fixtures. `make fuzz-run-<name>` hands that
directory to libFuzzer as its corpus, so a campaign writes its own units
there too; `tests/fuzz/corpus/.gitignore` tracks the seeds and ignores
everything else.

## 5. Departures from the suite conventions

Recorded in `CONVENTIONS.md` section 13.

- No `GSEC_Stream`. A caller already holds the buffer. Streaming a hash is a design of that hash, not a hole in the skeleton.
- No `_dump` of a secret. The suite's error object can name an offset in a file the caller handed in. A key is not that kind of input, and a working dump would be a disclosure primitive.
- `GSEC_ERR_MISMATCH` is added to the result vocabulary. A tag that does not match is the answer a verifier exists to give. `GSEC_ERR_INVALID` remains "the caller passed a bad argument".

## 6. What this library does not grow

`excluded` in the registry. A declaration is a failed build.

| Id | Why it is absent |
| --- | --- |
| `x448` | No caller asks for it. X25519 is the Montgomery key this library agrees. |

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
| 6 | Ed25519 is implemented | RFC 8032. Pure, a context, and the SHA-512 prehash. Verification rejects a non-canonical point and a non-canonical S |
| 7 | P-256 ECDH and ECDSA are implemented | ECDH rejects a non-canonical coordinate, an off-curve point, and infinity. ECDSA signs with RFC 6979, emits the low s, and accepts a high s |
| 8 | RSA-PSS and PKCS#1 v1.5 verification are implemented | Public exponent only. The DigestInfo is the DER encoding, including the NULL. A modulus past 4096 bits is rejected |
| 9 | RSA private signing is implemented | The exponentiation does not branch on the private exponent. The base is blinded. PKCS#1 v1.5 and PSS both sign. The PSS salt is the caller's. A modulus past 4096 bits is rejected |
| 10 | ECDSA P-384 is implemented | SHA-384 and RFC 6979. The signature is raw r then s. Signing emits the low s. Verification accepts a high s |
| 11 | AES-CBC is implemented | No padding. The initialization vector is the caller's. The mode does not authenticate. A repeated vector under one key leaks prefix equality |
| 12 | DES, RC2, and RC4 are implemented | All three are broken. Old formats still name them. RC2 and two-key Triple DES are here because PKCS#12 and PBES1 name them. None is constant-time |
| 13 | scrypt, bcrypt, and Argon2 are implemented | Password hashes for storage. Not PBKDF2. The salt is the caller's. The cost parameters are public. bcrypt is the $2b$ rule, which is also $2y$. $2a$ adds crypt_blowfish's collision tweak, and $2x$ is the sign-extending key schedule. `gsec_argon2` is version 0x13. `gsec_argon2_version` also accepts 0x10, which overwrites a block on later passes. A PHC string is `gsec_argon2_phc`. BLAKE2b stays inside Argon2 |
| 14 | Strict DER, PEM, unencrypted PKCS#8, and X.509 are implemented | A certificate is what phase 8 was for. The reader does not allocate and the parsed pointers address the caller's buffer. They live here until a certificates library takes them |
| 15 | P-384 ECDH and RSA encryption are implemented | TLS 1.2 names both: the curve for key agreement, and RSA key transport for a peer that offers no ECDHE. RSAES-PKCS1-v1_5 and RSAES-OAEP. A new encryption is OAEP, and a new key agreement is X25519 or P-256 |
| 16 | Encrypted PKCS#8, PKCS#12, a CRL, a basic OCSP response, and certificate issuance are implemented | What a caller holding a key file and checking a chain needs. PBES2 with AES for a new key or bag; PBES1 and the PKCS#12 PBE schemes are opened so an old file can be read, which is why RC2 and two-key Triple DES are public. Fetching a list or a response, and the operating system's trust store, stay with the caller |

Nonces are the caller's. The GCM and ChaCha20-Poly1305 declarations say what a repeated nonce
does. ECDSA signing uses RFC 6979 so the nonce is a
function of the key and the message. Verification accepts the encodings the
world produces, including a high `s`; signing emits the strict form.

The phase table above is the order. The argument for the set and for the
name stays with the suite's planning notes until the phase it describes
ships, and what has shipped is this file.
