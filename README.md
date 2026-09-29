# Ghoti.io Security

Cryptographic primitives in C. Hashes, message authentication, key
derivation, symmetric encryption, key agreement, signatures, password
hashes, and the kernel generator. Strict DER, PEM, PKCS#8, PKCS#12,
X.509, a certificate revocation list, and a basic OCSP response live
here until a certificates library takes them. Fetching a list or a
response, and reading an operating-system trust store, stay with the
caller. A handshake does not live here.

## Algorithms

This is what the library implements. A scheme that should not be used
for new work says so here and names the alternative. The headers say
the same thing next to the function. Known-answer files and what
`make check-oracle` runs are in
[documentation/oracles.md](documentation/oracles.md).

### Hashes

| Algorithm | |
| --- | --- |
| SHA-256, SHA-384, SHA-512 | One-shot and streaming. |
| SHA-1 | For ZIP and an old certificate. A new digest is SHA-256. |
| MD5 | For an ICC profile identifier and an old certificate. A new digest is SHA-256. HMAC does not take it. |

### Message authentication and derivation

| Algorithm | |
| --- | --- |
| HMAC | SHA-256, SHA-384, or SHA-512. SHA-1 checks an old MAC. |
| HKDF | High-entropy input. |
| PBKDF2 | A key from a password. It is not HKDF, and it is not a password hash. A new derivation uses SHA-256 or stronger. |

### Symmetric ciphers

| Algorithm | |
| --- | --- |
| AES-128, AES-192, AES-256 | One block. |
| AES-CTR | The NIST counter, or the WinZip counter. It does not authenticate. A caller that needs a tag uses AES-GCM. |
| AES-CBC | No padding and no tag. A caller that needs a tag uses AES-GCM. |
| AES-GCM | One shot, at 128, 192, and 256 bits. |
| ChaCha20-Poly1305 | One shot. A 32-byte key and a 12-byte nonce. |
| DES, two-key and three-key Triple DES | For an old file. A new cipher is AES-GCM or ChaCha20-Poly1305. |
| RC2 | For PKCS#12 and PBES1. A new cipher is AES-GCM or ChaCha20-Poly1305. |
| RC4 | For an old file. A new cipher is AES-GCM or ChaCha20-Poly1305. |

### Key agreement and signatures

| Algorithm | |
| --- | --- |
| X25519 | A 32-byte scalar. |
| Ed25519 | Pure, a context, or the SHA-512 prehash. |
| P-256 and P-384 ECDH | The scalar and the point. |
| ECDSA P-256 and P-384 | RFC 6979. SHA-256 on P-256, SHA-384 on P-384. |
| RSA signatures | PKCS#1 v1.5 and PSS. A new RSA signature is PSS with SHA-256 or stronger. MD5 and SHA-1 verify so an old certificate can be rejected for the algorithm. |
| RSAES-PKCS1-v1_5 | TLS 1.2 key transport. A new encryption is OAEP. A new key agreement is X25519 or P-256. |
| RSAES-OAEP | One hash for the label and for MGF1, or the two hashes separately. |

### Password hashes

These store a password. The salt is the caller's. A new store uses
Argon2id.

| Algorithm | |
| --- | --- |
| Argon2 | `gsec_argon2` is version `0x13`. Argon2id is the type for a new store. Version `0x10` checks an old hash. |
| scrypt | A store that already uses scrypt. |
| bcrypt | `$2b$`, `$2y$`, `$2a$`, and `$2x$`, to check an old hash. A new store uses Argon2id. |

### Keys and certificates

These stay here until a certificates library takes them. A critical
extension the parser does not understand is rejected. The pointers in a
parsed result address the caller's buffer.

| Algorithm | |
| --- | --- |
| DER | One strict value. The reader does not allocate. |
| PEM | The first block. |
| PKCS#8 | An unencrypted key, or PBES2. PBES1 is opened so an old key can be read. A new encrypted key is PBES2 with AES. |
| PKCS#12 | A PFX, and it must carry a MacData: an archive with none is unauthenticated and is refused. A new encrypted bag is PBES2 with AES. The older schemes are opened so an old archive can be read. |
| X.509 | One certificate, a signature check, a path, and a name match. The caller supplies the chain and the time. The path refuses MD5 and SHA-1, an RSA key below 2048 bits, and an expired anchor, and checks the leaf's extendedKeyUsage against a purpose the caller names. It does not check revocation. |
| Issuance | A certificate signed with P-256, P-384, Ed25519, or RSA. |
| CRL | Parse, check the signature, and look up a serial. Fetching the list stays with the caller. |
| OCSP | A basic response, with `producedAt`, `thisUpdate` and `nextUpdate`, because a signed response with no visible age can be replayed. Fetching it, judging its freshness, and a delegated responder all stay with the caller. |

## Before you call it

- A comparison of secret bytes goes through `gsec_equal`. It returns `GSEC_OK` or `GSEC_ERR_MISMATCH`. A wrong tag is a status, not a boolean, and `GSEC_OK` is the only success. `memcmp` anywhere under `src/` fails `make test`.
- `gsec_wipe` overwrites a region through a volatile store, so a later optimisation pass cannot delete the write.
- Verification returns `GSEC_ERR_MISMATCH` when the tag, MAC, or signature does not match.
- `gsec_x509_path` is where a trust policy lives: MD5 and SHA-1 links, RSA keys below `GSEC_X509_RSA_MIN_BITS`, and an anchor outside its own validity period are `GSEC_ERR_UNSUPPORTED` or `GSEC_ERR_MISMATCH` there, while `gsec_x509_signed_by` still verifies a weak signature so an old certificate can be identified before it is refused. Pass a `GSEC_X509_EKU_*` purpose, or check it yourself with `gsec_x509_purpose`: without one, a certificate issued for e-mail is a valid TLS certificate as far as the path is concerned.
- `gsec_result_string` returns one of a fixed set of static strings. There is no function that prints a key.
- `NULL` for an allocator is cutil's default. `NULL` for limits is `gsec_limits_default`, which caps one `gsec_random_bytes` call at 1 MiB and a password-based derivation at `GSEC_PBE_ITERATIONS_DEFAULT` iterations. That second cap is the one to lower when the files come from outside: the iteration count is in the file, and the default ceiling is about nine seconds of CPU.
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

`make test` is the suite: the unit tests, and the symbol, aliasing, stamp,
secret, hardening, depfile, static-analysis, foundation, constant-time and
fuzz-flag gates. Each of those is written so that it fails when the thing it
guards stops being true - most of them by planting a violation and requiring
it to be reported. `make help` lists the rest.

| Target | What it does |
| --- | --- |
| `make test-asan` | Rebuild with ASan and UBSan and run the suite |
| `make test-valgrind` | Run the suite under Valgrind |
| `make check-ct` | The constant-time gate. Needs memcheck |
| `make analyze` | GCC's `-fanalyzer` over `src/`, slower than the gate |
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
- **`aes.h`**, **`aes_ctr.h`**, **`aes_cbc.h`**, **`aes_gcm.h`**, **`chacha20_poly1305.h`**, **`des.h`**, **`rc2.h`**, **`rc4.h`** — one cipher or mode.
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

The algorithms in the tables above are implemented. Known-answer files are in
[documentation/oracles.md](documentation/oracles.md). The Windows
`BCryptGenRandom` path is written and has not been compiled.

`make test` is 180 tests and ten gates. `make test-asan`, `make test-valgrind`
and `make check-oracle` are clean, and every fuzz harness runs without a trap -
which means something it did not mean before 2026-09-28, because the fuzz build
now turns undefined behaviour into a failing run rather than a printed
diagnostic and a zero exit.

The library was audited on 2026-09-28 by a reader who had not written it, and
the findings were fixed in the fifteen commits from `6b268eb` to `c4112a7`.
What that changed, for anyone who had already read this file: `gsec_x509_path`
refuses MD5 and SHA-1 links, RSA keys under 2048 bits and an expired anchor,
and takes an extendedKeyUsage purpose; `gsec_pkcs12_open` refuses an archive
with no MacData; `gsec_ocsp_status` reports the times that make a replayed
response visible; and `gsec_pkcs8_decrypt` and `gsec_pkcs12_open` take a
`GSEC_Limits *` so the caller bounds the derivation work a file can ask for.

## License

LGPL-3.0-only. See [COPYING.LESSER](COPYING.LESSER) for the license, and
[COPYING](COPYING) for the GPL text it is written as additional permissions
on top of.

To report a vulnerability, see [SECURITY.md](SECURITY.md), which also lists
the behaviour that is deliberate - the broken algorithms an old format still
needs, what is not constant-time and why - and what this library guarantees
about threads.

Contributions are not being accepted at this time; see
[CONTRIBUTING.md](CONTRIBUTING.md) for what is useful instead.
