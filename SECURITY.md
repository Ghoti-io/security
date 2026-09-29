# Reporting a vulnerability

Email **pennycuff.c@gmail.com** with `ghoti.io-security` in the subject. A
proof of concept, the commit you tested, and the platform are the three
things that make a report actionable fastest.

There is no bug bounty and no formal service level. What there is: an
acknowledgement, a fix or an explanation of why the behaviour is what it is,
and credit in the commit message unless you would rather not have it.

Please do report anything in the list below. A report is not wasted for being
one of these; they are listed because they are the ones most likely to be
mistaken for intended behaviour.

## Things that are deliberate

Not vulnerabilities, so a report about them will get an explanation rather
than a fix. All of them are in the headers as well; this list is here so that
the answer arrives before the effort does.

- **MD5, SHA-1, DES, RC2 and RC4 exist.** Old formats name them: a ZIP file,
  an ICC profile identifier, PKCS#12, PBES1. They are reachable so that a file
  that uses them can be read, each header says what to use instead, and none
  of them is constant-time. `gsec_x509_path` refuses MD5 and SHA-1 in a chain,
  which is the place where the choice is a trust decision rather than a
  caller's.
- **The password hashes are not constant-time.** scrypt, bcrypt and Argon2
  index memory from the password by design; that is what makes them memory
  hard. They are excluded from `make check-ct` for that reason.
- **A successful `gsec_pkcs8_decrypt` is not an integrity check.** PBES2 with
  a CBC cipher, and every PBES1 scheme, has no MAC. See pkcs8.h.
- **Nonces are the caller's**, except where the algorithm defines them. A
  repeated GCM or ChaCha20-Poly1305 nonce under one key destroys
  authentication, and both declarations say so.
- **Revocation is the caller's.** `gsec_x509_path` does not fetch a CRL or an
  OCSP response, and does not check one it was not given.
- **Freshness is the caller's.** `gsec_ocsp_status` reports what the response
  says; comparing `this_update` and `next_update` against a clock is the
  caller's job, and a replayed response is a caller bug rather than a library
  one.
- **There is no minimum RSA key size in the primitives.** `rsa.h` will verify
  with a 512-bit key, because a self-test and two fuzz harnesses sign with one
  deliberately. `gsec_x509_path` enforces `GSEC_X509_RSA_MIN_BITS` instead,
  which is where a weak key is a trust decision.

## Things that are not deliberate

Worth a report, and the shapes most likely to matter here:

- A data-dependent branch or memory access on a secret in anything
  `tools/ct/clean.c` poisons - or an argument that something it does not
  poison should be poisoned.
- Any read or write outside a buffer, including one only a sanitizer would
  see. `make test-asan`, `make test-valgrind` and `make fuzz` are the three
  that look for these; a case any of them misses is worth more than one they
  catch.
- A malformed certificate, CRL, OCSP response, PKCS#8 key or PKCS#12 archive
  that is *accepted*. `tests/unit/test_negative.cpp` is where a case like that
  belongs, and one that survives those sweeps is exactly the report wanted.
- A chain that `gsec_x509_path` validates and should not.
- A signature, MAC or tag that verifies and should not, or a known answer this
  library gets wrong. `make check-oracle` compares against a pinned OpenSSL
  and Wycheproof; a disagreement it does not run is a real finding.

## Threading

Every function here is safe to call from several threads at once **on
separate arguments**: there is no global or `static` mutable state in `src/`,
and no hidden cache, lock or lazy initialisation. Two threads sharing one
context object - a `GSEC_Sha256` mid-stream, say - is the caller's to
serialise, exactly as for any other struct.

The one library-wide dependency is the kernel: `gsec_random_bytes` calls
`getrandom`, `getentropy` or `BCryptGenRandom` directly, with no buffer or
generator state of its own, so it is thread-safe and fork-safe without any
work from the caller.
