# Oracles

The algorithms this library implements are judged by something that is
not this library. `make check-oracle` first checks that the image still
produces the published SHA-256 of `abc` and the Wycheproof file the pin
names. It then judges every implemented primitive that has an outside
judge: the hashes, including MD5, HMAC, HKDF, PBKDF2, AES, AES-CTR, AES-CBC,
DES, RC4, scrypt, and Argon2, against OpenSSL in the image, and the AEAD
algorithms, the curves, including P-384, ECDSA, RSA verification, and
RSAES-OAEP against the pinned Wycheproof files. bcrypt is judged by
libxcrypt in the same image. RSA signing, and RSAES-PKCS1-v1_5, are judged
by a 2048-bit key the image generates. OpenSSL also writes a certificate,
its PEM, and an unencrypted PKCS#8 key, and this library reads them. A
difference fails the target.

`make test` does not run a container. A checkout with no container runtime
still builds and tests. The differential is a separate target, and that
target fails closed.

## The image

`localhost/ghoti-security-oracle-openssl:3.5.7`, built from
`tools/oracle/containers/openssl/Containerfile`.

```
make oracle-build
make check-oracle
```

`oracle-build` uses `docker build`. The tag is local. `oracle_env.py` does
not pull an image whose name starts with `localhost/`; a missing image is
an error that names `make oracle-build`.

The finished image has no digest to pin. Two builds of one Containerfile
are not two copies of one image. What is pinned is everything the build
reads, and the run-time check runs whether the probe is inside the
container or on the host (`GHOTI_ORACLE=host`).

| What | Pin |
| --- | --- |
| Base | `docker.io/library/debian:13-slim` at `sha256:7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c` |
| Package | `openssl=3.5.7-1~deb13u2` and `libssl-dev` at the same version, from the `trixie-security` suite the base image already lists. `libcrypt-dev=1:4.4.38-1` is libxcrypt, for bcrypt. `libc6-dev=2.41-12+deb13u4` and `gcc=4:14.2.0-1` compile the two helpers in the image. A second source line for that suite is rejected, because the image signs it with `debian-archive-keyring.pgp`. Main may still be on an older openssl, and an unpinned install would take it. |
| Reported version | `OpenSSL 3.5.7` followed by a space. `OpenSSL 3.5.70` does not match. |
| Wycheproof | C2SP commit `3fa63dd0344abb611f1fb1d77e119938603ea230` |
| Corpus | SHA-256 of `testvectors_v1/aes_gcm_test.json` at that commit, in `tools/oracle/containers/CORPUS` |

The apt pin stops resolving when the archive drops that revision. That
failure is the pin working: the alternative is an oracle that moved and a
diff that changed meaning with it.

`tools/oracle/containers/IMAGES` is the registry `docs.sh` reads. The
version column is what the reference must report. For OpenSSL that is the
library version, because a disagreement with NIST's SHA-256(`abc`) is about
OpenSSL 3.5.7. For Wycheproof the version is the commit, because the
vectors are the data.

## What `check-oracle` runs

`GHOTI_ORACLE_REQUIRED=1`, so a missing runtime, a missing image, or a
probe that exits non-zero is a failure. The probe is
`tools/oracle/openssl_kat.py`:

- SHA-256 of `abc` is `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.
- `sha256sum` of each file named in `CORPUS` matches the digest on that line.

Those two checks judge the oracle. The messages after them judge
`gsec_sha256`: empty, `abc`, the RFC 6234 two-block string, the padding
lengths 55 through 65, a thousand `a` bytes, and the bytes 0 through 255.
Each is hashed in one call and in chunks of 1 and of 64. The helper is
`examples/sha256.c`, which `make check-oracle` builds and passes as
`GSEC_SHA256_BIN`. SHA-512 and SHA-384 use `examples/hash.c`
(`GSEC_HASH_BIN`) the same way, with chunks of 1 and of 128, and with the
padding lengths 111 through 129. SHA-1 uses the same helper, with the
SHA-256 padding lengths and chunks of 1 and of 64. `tools/oracle/primitives.txt`
lists those rows as `implemented` with judge `openssl`. AES-GCM and
ChaCha20-Poly1305 are judged by the pinned Wycheproof files, because
`openssl enc` does not implement an AEAD. The ChaCha20-Poly1305 row's
committed vector is the RFC 8439 case; the oracle runs the rest.
X25519 is the same shape: the committed vector is RFC 7748, and the oracle
runs the pinned Wycheproof file. A `valid` case must match. An `acceptable`
case may be rejected, which is how the all-zero shared secret is handled,
or it must match. Ed25519 is the same shape: the committed vector is RFC 8032,
and the oracle runs the pinned Wycheproof file. A `valid` case must be
accepted. An `invalid` case, including a non-canonical S, must be rejected.
P-256 ECDH is judged by the pinned Wycheproof ecpoint file. The committed
vector is one of those cases. A `valid` case must match the shared x. An
`invalid` case, and a compressed point, must be rejected. ECDSA P-256 is
the same shape: the committed vector is RFC 6979, and the oracle runs the
pinned Wycheproof P1363 file. A `valid` case must be accepted. An
`invalid` case, including an r or s of zero, must be rejected. ECDSA
P-384 is the same shape against
`ecdsa_secp384r1_sha384_p1363_test.json`: a `valid` case must be accepted,
and an `invalid` case must be rejected. RSA
verification is judged by the pinned Wycheproof files. A `valid` case must
be accepted. An `invalid` case must be rejected, and so must an
`acceptable` one: that is a BER DigestInfo or a missing NULL, and this
library does not take it. RSA signing generates a 2048-bit key in the
image, signs the ASCII bytes of `sample` with this library, and asks
OpenSSL to verify the PKCS#1 v1.5 signature and a PSS signature whose salt
is 32 bytes. The known answers in `rsa_private.vec` are the unblinded
private exponentiation, which blinding must not change. HMAC is
compared the same way: `examples/hmac.c` (`GSEC_HMAC_BIN`) against
`openssl dgst -mac HMAC`. HKDF uses `examples/hkdf.c` (`GSEC_HKDF_BIN`)
against `openssl kdf HKDF`. PBKDF2 uses `examples/pbkdf2.c`
(`GSEC_PBKDF2_BIN`) against `openssl kdf PBKDF2`. Argon2 uses
`examples/argon2.c` against `openssl kdf ARGON2D`, `ARGON2I`, and
`ARGON2ID`, including the secret and the associated data from RFC 9106.
bcrypt uses `examples/bcrypt.c` against `crypt-bcrypt` in the image,
which calls libxcrypt's `crypt_r`. The comparison is the 23 bytes the
modular-crypt string stores. `$2a$`, `$2b$`, and `$2x$` each call their
function. `$2y$` is asked of libxcrypt and compared with `gsec_bcrypt`. P-384 ECDH runs
`ecdh_secp384r1_ecpoint_test.json`. RSAES-OAEP runs the pinned files
whose label hash and MGF1 hash are the same. RSAES-PKCS1-v1_5 encrypts
a fresh message with `openssl pkeyutl` and decrypts it here. RC4's short
keys go through `rc4-evp`, because `openssl enc -rc4` zero-pads `-K`.
DER, PEM, PKCS#8, and X.509 read objects OpenSSL just wrote.

A host-mode run (`GHOTI_ORACLE=host`) uses the `openssl` on `PATH` and still
requires the version string. It is a way to run the probe without a
container. It is not a second pin: the container is the one `check-oracle`
builds against.

## The committed corpus

`tests/data/vectors/` holds known-answer files the unit tests score, with
no container. `tests/data/vectors/MANIFEST` is the SHA-256 of each file.
`check-foundation` recomputes those hashes. A vector file that is edited
without updating the manifest fails the build, which is the property a
hand-edited expected digest would not have.

The parser rejects a truncated hex string, an odd number of digits, an
uppercase digit, a boolean expectation, and a length that does not match
the bytes. `equal`, the five hashes, `hmac`, `hkdf`, `pbkdf2`, `aes`,
`aes_ctr`, `aes_cbc`, `des`, `rc4`, `scrypt`, `bcrypt`, `argon2`, `aes_gcm`, `chacha20_poly1305`, `x25519`, `ed25519`,
`ecdh_p256`, `ecdh_p384`, `ecdsa_p256`, `ecdsa_p384`, `rsa_pkcs1`, `rsa_pss`, `rsa_private`,
`rsa_oaep`, `rsaes_pkcs1`, `der`, `pem`, `pkcs8`, and `x509` each have a file. A
later primitive adds a file in the same commit as the function, and names
it on the registry row.
