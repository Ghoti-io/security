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
"""Ask the pinned image whether it is the reference, then whether we match it.

SHA-256 of the three bytes 61 62 63 is the NIST known answer
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.
Wycheproof's aes_gcm_test.json at the pinned commit has the digest in
containers/CORPUS. Those two checks judge the oracle. The messages after
them are hashed by this library and by `openssl dgst -sha256` in the
image, and the digests must be the same. GSEC_SHA256_BIN is that library,
built by `make check-oracle`.
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
    return diff_library()


def openssl_digest(data):
    proc = subprocess.run(
        oracle_env.command("openssl", ["openssl", "dgst", "-sha256"]),
        input=data, capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(1)
    return last_field(proc.stdout.decode("utf-8", "replace"))


def library_digest(binary, data, chunk):
    command = [binary] if chunk is None else [binary, "--chunk", str(chunk)]
    proc = subprocess.run(command, input=data, capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        sys.stderr.write("sha256 helper exited %s\n" % proc.returncode)
        raise SystemExit(1)
    got = proc.stdout.decode("utf-8", "replace").strip()
    if len(got) != 64:
        sys.stderr.write("sha256 helper wrote %r\n" % got)
        raise SystemExit(1)
    return got


def diff_library():
    binary = os.environ.get("GSEC_SHA256_BIN", "")
    if not binary:
        sys.stderr.write("GSEC_SHA256_BIN is not set\n")
        return 1
    messages = [
        ("empty", b""),
        ("abc", b"abc"),
        ("two-block",
         b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        ("pad-55", b"a" * 55),
        ("pad-56", b"a" * 56),
        ("pad-63", b"a" * 63),
        ("pad-64", b"a" * 64),
        ("pad-65", b"a" * 65),
        ("thousand", b"a" * 1000),
        ("bytes", bytes(range(256))),
    ]
    for name, data in messages:
        want = openssl_digest(data)
        for chunk in (None, 1, 64):
            got = library_digest(binary, data, chunk)
            if not compare.hex_equal(got, want):
                how = "oneshot" if chunk is None else "chunk %s" % chunk
                sys.stderr.write(
                    "%s %s is %s, openssl says %s\n" % (name, how, got, want))
                return 1
        print("sha256 %s %s" % (name, want))
    return diff_wide()


def openssl_wide(flag, data):
    proc = subprocess.run(
        oracle_env.command("openssl", ["openssl", "dgst", flag]),
        input=data, capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(1)
    return last_field(proc.stdout.decode("utf-8", "replace"))


def library_wide(binary, alg, data, chunk, hexlen):
    command = [binary, alg] if chunk is None else [binary, alg, "--chunk", str(chunk)]
    proc = subprocess.run(command, input=data, capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        sys.stderr.write("%s helper exited %s\n" % (alg, proc.returncode))
        raise SystemExit(1)
    got = proc.stdout.decode("utf-8", "replace").strip()
    if len(got) != hexlen:
        sys.stderr.write("%s helper wrote %r\n" % (alg, got))
        raise SystemExit(1)
    return got


def diff_wide():
    binary = os.environ.get("GSEC_HASH_BIN", "")
    if not binary:
        sys.stderr.write("GSEC_HASH_BIN is not set\n")
        return 1
    messages = [
        ("empty", b""),
        ("abc", b"abc"),
        ("two-block",
         b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        ("pad-111", b"a" * 111),
        ("pad-112", b"a" * 112),
        ("pad-127", b"a" * 127),
        ("pad-128", b"a" * 128),
        ("pad-129", b"a" * 129),
        ("thousand", b"a" * 1000),
        ("bytes", bytes(range(256))),
    ]
    algs = (("sha512", "-sha512", 128), ("sha384", "-sha384", 96))
    for alg, flag, hexlen in algs:
        for name, data in messages:
            want = openssl_wide(flag, data)
            for chunk in (None, 1, 128):
                got = library_wide(binary, alg, data, chunk, hexlen)
                if not compare.hex_equal(got, want):
                    how = "oneshot" if chunk is None else "chunk %s" % chunk
                    sys.stderr.write(
                        "%s %s %s is %s, openssl says %s\n"
                        % (alg, name, how, got, want))
                    return 1
            print("%s %s %s" % (alg, name, want))
    return diff_sha1()


def diff_sha1():
    binary = os.environ.get("GSEC_HASH_BIN", "")
    if not binary:
        sys.stderr.write("GSEC_HASH_BIN is not set\n")
        return 1
    messages = [
        ("empty", b""),
        ("abc", b"abc"),
        ("two-block",
         b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        ("pad-55", b"a" * 55),
        ("pad-56", b"a" * 56),
        ("pad-63", b"a" * 63),
        ("pad-64", b"a" * 64),
        ("pad-65", b"a" * 65),
        ("thousand", b"a" * 1000),
        ("bytes", bytes(range(256))),
    ]
    for name, data in messages:
        want = openssl_wide("-sha1", data)
        for chunk in (None, 1, 64):
            got = library_wide(binary, "sha1", data, chunk, 40)
            if not compare.hex_equal(got, want):
                how = "oneshot" if chunk is None else "chunk %s" % chunk
                sys.stderr.write(
                    "sha1 %s %s is %s, openssl says %s\n" % (name, how, got, want))
                return 1
        print("sha1 %s %s" % (name, want))
    return diff_md5()


def diff_md5():
    binary = os.environ.get("GSEC_HASH_BIN", "")
    if not binary:
        sys.stderr.write("GSEC_HASH_BIN is not set\n")
        return 1
    messages = [
        ("empty", b""),
        ("abc", b"abc"),
        ("message-digest", b"message digest"),
        ("eighty",
         b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
        ("pad-55", b"a" * 55),
        ("pad-56", b"a" * 56),
        ("pad-63", b"a" * 63),
        ("pad-64", b"a" * 64),
        ("pad-65", b"a" * 65),
        ("thousand", b"a" * 1000),
        ("bytes", bytes(range(256))),
    ]
    for name, data in messages:
        want = openssl_wide("-md5", data)
        for chunk in (None, 1, 64):
            got = library_wide(binary, "md5", data, chunk, 32)
            if not compare.hex_equal(got, want):
                how = "oneshot" if chunk is None else "chunk %s" % chunk
                sys.stderr.write(
                    "md5 %s %s is %s, openssl says %s\n" % (name, how, got, want))
                return 1
        print("md5 %s %s" % (name, want))
    return diff_hmac()


def openssl_hmac(flag, key_hex, data):
    proc = subprocess.run(
        oracle_env.command("openssl", [
            "openssl", "dgst", flag, "-mac", "HMAC",
            "-macopt", "hexkey:" + key_hex]),
        input=data, capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(1)
    return last_field(proc.stdout.decode("utf-8", "replace"))


def library_hmac(binary, alg, key_hex, data, chunk, hexlen):
    command = [binary, alg, key_hex] if chunk is None else [
        binary, alg, key_hex, "--chunk", str(chunk)]
    proc = subprocess.run(command, input=data, capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        sys.stderr.write("hmac helper exited %s\n" % proc.returncode)
        raise SystemExit(1)
    got = proc.stdout.decode("utf-8", "replace").strip()
    if len(got) != hexlen:
        sys.stderr.write("hmac helper wrote %r\n" % got)
        raise SystemExit(1)
    return got


def diff_hmac():
    binary = os.environ.get("GSEC_HMAC_BIN", "")
    if not binary:
        sys.stderr.write("GSEC_HMAC_BIN is not set\n")
        return 1
    hi = "0b" * 20
    long_key = "aa" * 131
    cases = [
        ("sha1", "-sha1", 40, hi, b"Hi There"),
        ("sha256", "-sha256", 64, hi, b"Hi There"),
        ("sha384", "-sha384", 96, hi, b"Hi There"),
        ("sha512", "-sha512", 128, hi, b"Hi There"),
        ("sha256", "-sha256", 64, long_key,
         b"Test Using Larger Than Block-Size Key - Hash Key First"),
        ("sha512", "-sha512", 128, long_key,
         b"Test Using Larger Than Block-Size Key - Hash Key First"),
        ("sha256", "-sha256", 64, "6b6579", b""),
    ]
    for alg, flag, hexlen, key, data in cases:
        want = openssl_hmac(flag, key, data)
        for chunk in (None, 1):
            got = library_hmac(binary, alg, key, data, chunk, hexlen)
            if not compare.hex_equal(got, want):
                how = "oneshot" if chunk is None else "chunk 1"
                sys.stderr.write(
                    "hmac %s %s is %s, openssl says %s\n" % (alg, how, got, want))
                return 1
        print("hmac %s %s" % (alg, want))
    return diff_hkdf()


def colon_hex(text):
    return "".join(ch for ch in text.lower() if ch in "0123456789abcdef")


def openssl_hkdf(digest, ikm, salt, info, n):
    command = [
        "openssl", "kdf", "-keylen", str(n), "-digest", digest,
        "-kdfopt", "hexkey:" + ikm]
    if salt:
        command.extend(["-kdfopt", "hexsalt:" + salt])
    if info:
        command.extend(["-kdfopt", "hexinfo:" + info])
    command.append("HKDF")
    proc = subprocess.run(
        oracle_env.command("openssl", command), capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(1)
    got = colon_hex(proc.stdout.decode("utf-8", "replace"))
    if len(got) != n * 2:
        sys.stderr.write("openssl hkdf wrote %r\n" % got)
        raise SystemExit(1)
    return got


def library_hkdf(binary, alg, ikm, salt, info, n):
    proc = subprocess.run(
        [binary, alg, ikm, salt if salt else "-", info if info else "-", str(n)],
        capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        sys.stderr.write("hkdf helper exited %s\n" % proc.returncode)
        raise SystemExit(1)
    got = proc.stdout.decode("utf-8", "replace").strip()
    if len(got) != n * 2:
        sys.stderr.write("hkdf helper wrote %r\n" % got)
        raise SystemExit(1)
    return got


def diff_hkdf():
    binary = os.environ.get("GSEC_HKDF_BIN", "")
    if not binary:
        sys.stderr.write("GSEC_HKDF_BIN is not set\n")
        return 1
    ikm = "0b" * 22
    ikm_sha1 = "0b" * 11
    salt = "000102030405060708090a0b0c"
    info = "f0f1f2f3f4f5f6f7f8f9"
    cases = [
        ("sha256", "SHA256", ikm, salt, info, 42),
        ("sha256", "SHA256", ikm, "", "", 42),
        ("sha1", "SHA1", ikm_sha1, salt, info, 42),
        ("sha384", "SHA384", ikm, salt, info, 42),
        ("sha512", "SHA512", ikm, salt, info, 42),
    ]
    for alg, digest, key, salt_hex, info_hex, n in cases:
        want = openssl_hkdf(digest, key, salt_hex, info_hex, n)
        got = library_hkdf(binary, alg, key, salt_hex, info_hex, n)
        if not compare.hex_equal(got, want):
            sys.stderr.write("hkdf %s is %s, openssl says %s\n" % (alg, got, want))
            return 1
        print("hkdf %s %s" % (alg, want))
    return diff_pbkdf2()


def openssl_pbkdf2(digest, password, salt, iterations, n):
    command = [
        "openssl", "kdf", "-keylen", str(n), "-digest", digest,
        "-kdfopt", "hexpass:" + password]
    if salt:
        command.extend(["-kdfopt", "hexsalt:" + salt])
    command.extend(["-kdfopt", "iter:" + str(iterations), "PBKDF2"])
    proc = subprocess.run(
        oracle_env.command("openssl", command), capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(1)
    got = colon_hex(proc.stdout.decode("utf-8", "replace"))
    if len(got) != n * 2:
        sys.stderr.write("openssl pbkdf2 wrote %r\n" % got)
        raise SystemExit(1)
    return got


def library_pbkdf2(binary, alg, password, salt, iterations, n):
    proc = subprocess.run(
        [binary, alg, password if password else "-", salt if salt else "-",
         str(iterations), str(n)],
        capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        sys.stderr.write("pbkdf2 helper exited %s\n" % proc.returncode)
        raise SystemExit(1)
    got = proc.stdout.decode("utf-8", "replace").strip()
    if len(got) != n * 2:
        sys.stderr.write("pbkdf2 helper wrote %r\n" % got)
        raise SystemExit(1)
    return got


def diff_pbkdf2():
    binary = os.environ.get("GSEC_PBKDF2_BIN", "")
    if not binary:
        sys.stderr.write("GSEC_PBKDF2_BIN is not set\n")
        return 1
    password = "70617373776f7264"
    salt = "73616c74"
    cases = [
        ("sha1", "SHA1", password, salt, 1, 20),
        ("sha1", "SHA1", password, salt, 2, 20),
        ("sha1", "SHA1", password, salt, 4096, 20),
        ("sha1", "SHA1", "7061737300776f7264", "7361006c74", 4096, 16),
        ("sha256", "SHA256", password, salt, 2, 32),
        ("sha384", "SHA384", password, salt, 1, 48),
        ("sha512", "SHA512", password, salt, 1, 64),
    ]
    for alg, digest, key, salt_hex, iterations, n in cases:
        want = openssl_pbkdf2(digest, key, salt_hex, iterations, n)
        got = library_pbkdf2(binary, alg, key, salt_hex, iterations, n)
        if not compare.hex_equal(got, want):
            sys.stderr.write(
                "pbkdf2 %s c=%s is %s, openssl says %s\n"
                % (alg, iterations, got, want))
            return 1
        print("pbkdf2 %s %s" % (alg, want))
    return 0


if __name__ == "__main__":
    sys.exit(main())
