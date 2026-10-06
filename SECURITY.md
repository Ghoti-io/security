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
  of them is constant-time. The certificate library's path validation refuses
  MD5 and SHA-1 in a chain, which is the place where the choice is a trust
  decision rather than a caller's.
- **The password hashes are not constant-time.** scrypt, bcrypt and Argon2
  index memory from the password by design; that is what makes them memory
  hard. They are excluded from `make check-ct` for that reason.
- **Nonces are the caller's**, except where the algorithm defines them. A
  repeated GCM or ChaCha20-Poly1305 nonce under one key destroys
  authentication, and both declarations say so.
- **There is no minimum RSA key size in the primitives.** `rsa.h` will verify
  with a 512-bit key, because a self-test and two fuzz harnesses sign with one
  deliberately. The certificate library's path validation enforces a minimum
  instead, which is where a weak key is a trust decision.

## Things that are not deliberate

Worth a report, and the shapes most likely to matter here:

- A data-dependent branch or memory access on a secret in anything
  `tools/ct/clean.c` poisons - or an argument that something it does not
  poison should be poisoned.
- Any read or write outside a buffer, including one only a sanitizer would
  see. `make test-asan`, `make test-valgrind` and `make fuzz` are the three
  that look for these; a case any of them misses is worth more than one they
  catch.
