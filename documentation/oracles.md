# Oracles

The algorithms this library implements are judged by something that is
not this library. `make check-oracle` first checks that the image still
produces the published SHA-256 of `abc` and the Wycheproof file the pin
names. It then hashes the same messages with this library and with
`openssl dgst` in the image, for SHA-256, SHA-512, SHA-384, and SHA-1. A
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
| Package | `openssl=3.5.7-1~deb13u2` from the `trixie-security` suite the base image already lists. A second source line for that suite is rejected, because the image signs it with `debian-archive-keyring.pgp`. Main may still be on an older openssl, and an unpinned install would take it. |
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
- `sha256sum` of the pinned `aes_gcm_test.json` matches `CORPUS`.

Those two checks judge the oracle. The messages after them judge
`gsec_sha256`: empty, `abc`, the RFC 6234 two-block string, the padding
lengths 55 through 65, a thousand `a` bytes, and the bytes 0 through 255.
Each is hashed in one call and in chunks of 1 and of 64. The helper is
`examples/sha256.c`, which `make check-oracle` builds and passes as
`GSEC_SHA256_BIN`. SHA-512 and SHA-384 use `examples/hash.c`
(`GSEC_HASH_BIN`) the same way, with chunks of 1 and of 128, and with the
padding lengths 111 through 129. SHA-1 uses the same helper, with the
SHA-256 padding lengths and chunks of 1 and of 64. `tools/oracle/primitives.txt`
lists those rows as `implemented` with judge `openssl`. Declaring
`gsec_pbkdf2` while that row is still pending fails `make test`. HMAC is
compared the same way: `examples/hmac.c` (`GSEC_HMAC_BIN`) against
`openssl dgst -mac HMAC`. HKDF uses `examples/hkdf.c` (`GSEC_HKDF_BIN`)
against `openssl kdf HKDF`.

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
the bytes. `equal`, `sha256`, `sha512`, `sha384`, and `sha1` each have a file. A
later primitive adds a file in the same commit as the function, and names
it on the registry row.
