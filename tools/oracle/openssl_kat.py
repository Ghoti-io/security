#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
#
# Copyright (C) 2026 Corey Pennycuff
#
# This file is part of Ghoti.io Security.
#
# Ghoti.io Security is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3 as
# published by the Free Software Foundation.
"""Ask the pinned image two questions whose answers are already known.

SHA-256 of the three bytes 61 62 63 is the NIST known answer
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.
Wycheproof's aes_gcm_test.json at the pinned commit has the digest in
containers/CORPUS.

This does not test this library. It tests the oracle, before the oracle is
allowed to judge the library. A reference that cannot reproduce a published
digest is not a reference.
"""

import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare
import oracle_env

HERE = os.path.dirname(os.path.abspath(__file__))
SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
WYCHEPROOF_FILE = "/opt/wycheproof/testvectors_v1/aes_gcm_test.json"


def corpus_digest():
    path = os.path.join(HERE, "containers", "CORPUS")
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            digest, name = line.split()
            if name == "testvectors_v1/aes_gcm_test.json":
                return digest
    raise SystemExit("CORPUS has no digest for aes_gcm_test.json")


def last_field(text):
    parts = text.strip().split()
    if not parts:
        raise SystemExit("oracle produced no digest")
    return parts[-1]


def main():
    compare.self_test()
    sha = subprocess.run(
        oracle_env.command("openssl", ["openssl", "dgst", "-sha256"]),
        input=b"abc", capture_output=True)
    if sha.returncode != 0:
        sys.stderr.write(sha.stderr.decode("utf-8", "replace"))
        return 1
    got = last_field(sha.stdout.decode("utf-8", "replace"))
    if not compare.hex_equal(got, SHA256_ABC):
        sys.stderr.write(
            "openssl SHA-256(\"abc\") is %s, NIST says %s\n" % (got, SHA256_ABC))
        return 1
    print("sha256(abc) %s" % got)

    wy = subprocess.run(
        oracle_env.command("wycheproof", ["sha256sum", WYCHEPROOF_FILE]),
        capture_output=True)
    if wy.returncode != 0:
        sys.stderr.write(wy.stderr.decode("utf-8", "replace"))
        return 1
    # sha256sum prints "<digest>  <path>". openssl dgst prints the digest
    # last. Taking the last field here would compare the path.
    fields = wy.stdout.decode("utf-8", "replace").split()
    if not fields:
        sys.stderr.write("sha256sum produced no digest\n")
        return 1
    got = fields[0]
    want = corpus_digest()
    if not compare.hex_equal(got, want):
        sys.stderr.write(
            "wycheproof aes_gcm_test.json is %s, CORPUS says %s\n" % (got, want))
        return 1
    print("wycheproof aes_gcm_test.json %s" % got)
    return 0


if __name__ == "__main__":
    sys.exit(main())
