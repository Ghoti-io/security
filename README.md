# Ghoti.io Security

Cryptographic primitives: hashes, MACs, key derivation, authenticated
encryption, key agreement, signatures, and the entropy call. It does not
hold policy, certificates, or a handshake. `certificates` and `tls` are the
libraries those belong in; this one is the layer under them.

## What is implemented

Phase 0, the machinery the algorithms are measured against, SHA-256, SHA-512,
SHA-384, SHA-1, and HMAC over those four hashes. SHA-1 does not provide
collision resistance; it is here for ZIP and for old certificate chains.
No cipher is implemented yet.

- `gsec_equal` compares two regions and returns `GSEC_OK` or `GSEC_ERR_MISMATCH`. A wrong tag is a status, not a boolean.
- `gsec_wipe` overwrites a region through a volatile store, so a later optimisation pass cannot delete the write.
- `gsec_random_bytes` reads the kernel generator. A failure wipes what was already written and returns `GSEC_ERR_IO`. There is no userspace generator behind that failure.
- `gsec_sha256` hashes a buffer. `gsec_sha256_init`, `gsec_sha256_update`, and `gsec_sha256_final` hash a message in slices. Final wipes the context. `gsec_sha512`, `gsec_sha384`, and `gsec_sha1` are the same shape. SHA-384 is SHA-512's compression with a different initial value, not a truncation of a SHA-512 digest.
- `gsec_hmac` is HMAC over one of those hashes. `gsec_hmac_verify` compares the MAC with `gsec_equal` and returns `GSEC_ERR_MISMATCH` when it differs.
- `gsec_selftest` runs the known-answer checks an embedder can call at startup. That is the calls above, including each hash of the empty message and of `abc`, and the HMAC-SHA-256 of RFC 4231 test case 1.
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

[documentation/design.md](documentation/design.md) is the design: what phase 0
implements, the gates, and what the later phases are.
[documentation/oracles.md](documentation/oracles.md) is the pinned OpenSSL and
Wycheproof image. `make test` does not need it. `make check-oracle` fails if
the image is absent. `make docs` builds the manual.

## Status

Phase 1 of the plan is built: SHA-256, SHA-512, SHA-384, SHA-1, and HMAC.
`make test` runs the unit tests, the symbol, aliasing, stamp, secret,
foundation, and constant-time gates. `make check-oracle` is separate, because
it needs the container. It compares these hashes with the pinned OpenSSL.

## License

LGPL-3.0-only. See [COPYING.LESSER](COPYING.LESSER) for the license, and
[COPYING](COPYING) for the GPL text it is written as additional permissions
on top of.

Contributions are not being accepted at this time; see
[CONTRIBUTING.md](CONTRIBUTING.md) for what is useful instead.
