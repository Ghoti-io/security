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
"""The pins agree with each other, and the public API agrees with the registry.

No container. `make check-oracle` is the run that asks the image. This is the
run that fails when two files that are supposed to name one pin have drifted,
or when a primitive was declared without a row saying who judges it.

The classifier is run on a planted declaration before it is trusted on the
tree. A planted `gsec_aes_encrypt` while aes_encrypt is still pending
must be reported. If it is not, this program is not a gate. The plant moves to the
next pending primitive when one is implemented.
"""

import hashlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "oracle"))
import compare

ROOT = Path(__file__).resolve().parents[1]
INCLUDE = ROOT / "include"
REGISTRY = ROOT / "tools" / "oracle" / "primitives.txt"
MANIFEST = ROOT / "tests" / "data" / "vectors" / "MANIFEST"
IMAGES = ROOT / "tools" / "oracle" / "containers" / "IMAGES"
CORPUS = ROOT / "tools" / "oracle" / "containers" / "CORPUS"
CONTAINERFILE = ROOT / "tools" / "oracle" / "containers" / "openssl" / "Containerfile"

DEBIAN_DIGEST = (
    "sha256:7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c")
OPENSSL_APT = "openssl=3.5.7-1~deb13u2"
WYCHEPROOF = "3fa63dd0344abb611f1fb1d77e119938603ea230"
IMAGE = "localhost/ghoti-security-oracle-openssl:3.5.7"

FOUNDATION = {
    "gsec_allocator_default",
    "gsec_limits_default",
    "gsec_poison",
    "gsec_result_string",
    "gsec_selftest",
    "gsec_unpoison",
    "gsec_version_number",
    "gsec_version_string",
}

DECL = re.compile(r"GSEC_API\b.*\b(gsec_[a-z0-9_]+)\s*\(")


def fail(message):
    print("check-foundation: %s" % message, file=sys.stderr)
    sys.exit(1)


def parse_registry(text):
    rows = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 4:
            fail("primitives.txt: not four tab-separated fields: %r" % line)
        ident, status, judge, vectors = parts
        if status not in ("implemented", "pending", "excluded"):
            fail("primitives.txt: bad status %r" % status)
        rows.append({
            "id": ident,
            "status": status,
            "judge": judge,
            "vectors": vectors,
        })
    return rows


def matches(function, ident):
    prefix = "gsec_" + ident
    return function == prefix or function.startswith(prefix + "_")


def classify(functions, rows):
    problems = []
    claimed = set()
    for row in rows:
        hit = sorted(fn for fn in functions if matches(fn, row["id"]))
        if row["status"] == "implemented":
            if not hit:
                problems.append(
                    "%s is implemented and no gsec_%s function is declared"
                    % (row["id"], row["id"]))
            claimed.update(hit)
            if row["judge"] in ("openssl", "nist", "rfc", "wycheproof") \
                    and row["vectors"] == "-":
                problems.append(
                    "%s is judged by %s and has no vector file"
                    % (row["id"], row["judge"]))
        elif hit:
            problems.append(
                "%s is %s but declares %s"
                % (row["id"], row["status"], ", ".join(hit)))
    for function in sorted(functions):
        if function in FOUNDATION or function in claimed:
            continue
        problems.append(
            "%s is declared and is neither foundation nor an implemented "
            "primitive" % function)
    return problems


def declarations():
    found = set()
    for path in INCLUDE.rglob("*.h"):
        for line in path.read_text(encoding="utf-8").splitlines():
            match = DECL.search(line)
            if match:
                found.add(match.group(1))
    return found


def check_manifest():
    if not MANIFEST.is_file():
        fail("no %s" % MANIFEST.relative_to(ROOT))
    seen = []
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            fail("MANIFEST: expected digest and path: %r" % line)
        digest, rel = parts
        path = ROOT / rel
        if not path.is_file():
            fail("MANIFEST names a missing file: %s" % rel)
        got = hashlib.sha256(path.read_bytes()).hexdigest()
        if not compare.hex_equal(got, digest):
            fail("%s sha256 is %s, MANIFEST says %s" % (rel, got, digest))
        seen.append(rel)
    if not seen:
        fail("MANIFEST is empty")
    return seen


def main():
    compare.self_test()
    rows = parse_registry(REGISTRY.read_text(encoding="utf-8"))
    # The implemented set alone must be clean. Adding one pending primitive
    # must be reported. A classifier that only runs on the tree cannot tell
    # those apart: both look like whatever the headers happen to say.
    present = {
        "gsec_equal", "gsec_wipe", "gsec_random_bytes",
        "gsec_hmac", "gsec_hmac_init", "gsec_hmac_update",
        "gsec_hmac_final", "gsec_hmac_verify",
        "gsec_hkdf", "gsec_hkdf_extract", "gsec_hkdf_expand",
        "gsec_pbkdf2",
        "gsec_sha1", "gsec_sha1_init", "gsec_sha1_update",
        "gsec_sha1_final",
        "gsec_sha256", "gsec_sha256_init", "gsec_sha256_update",
        "gsec_sha256_final",
        "gsec_sha384", "gsec_sha384_init", "gsec_sha384_update",
        "gsec_sha384_final",
        "gsec_sha512", "gsec_sha512_init", "gsec_sha512_update",
        "gsec_sha512_final",
    }
    clean = classify(present, rows)
    if clean:
        fail("the implemented set was rejected: %r" % clean)
    planted = classify(present | {"gsec_aes_encrypt"}, rows)
    if not any("aes_encrypt" in item and "pending" in item for item in planted):
        fail("a planted gsec_aes_encrypt was not rejected: %r" % planted)

    functions = declarations()
    missing = sorted(FOUNDATION - functions)
    if missing:
        fail("foundation functions missing from the headers: %s"
            % ", ".join(missing))
    problems = classify(functions, rows)
    if problems:
        for problem in problems:
            print("check-foundation: " + problem, file=sys.stderr)
        return 1

    listed = check_manifest()
    for row in rows:
        if row["vectors"] == "-":
            continue
        path = ROOT / row["vectors"]
        if not path.is_file():
            fail("%s names a missing vector file %s" % (row["id"], row["vectors"]))
        if row["vectors"] not in listed:
            fail("%s is not in the vector MANIFEST" % row["vectors"])

    text = CONTAINERFILE.read_text(encoding="utf-8")
    for needle in (DEBIAN_DIGEST, OPENSSL_APT, WYCHEPROOF, "LANG=C.UTF-8",
            "trixie-security"):
        if needle not in text:
            fail("Containerfile does not pin %s" % needle)
    images = IMAGES.read_text(encoding="utf-8")
    if IMAGE not in images or "OpenSSL 3.5.7" not in images \
            or WYCHEPROOF not in images:
        fail("IMAGES does not name the openssl image, its version, and the "
             "wycheproof commit")
    corpus = CORPUS.read_text(encoding="utf-8")
    if "testvectors_v1/aes_gcm_test.json" not in corpus:
        fail("CORPUS does not name aes_gcm_test.json")
    digest = None
    for line in corpus.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        digest = line.split()[0]
    if digest is None or len(digest) != 64:
        fail("CORPUS digest is not 64 hex digits")
    print("check-foundation: registry, manifest, and oracle pins agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
