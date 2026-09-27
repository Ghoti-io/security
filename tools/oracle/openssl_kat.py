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
Wycheproof's aes_gcm_test.json, chacha20_poly1305_test.json,
x25519_test.json, ed25519_test.json, ecdh_secp256r1_ecpoint_test.json, and
ecdsa_secp256r1_sha256_p1363_test.json at the pinned commit have the
digests in containers/CORPUS.
Those checks judge the oracle. The messages after
them are hashed by this library and by `openssl dgst -sha256` in the
image, and the digests must be the same. GSEC_SHA256_BIN is that library,
built by `make check-oracle`.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare
import oracle_env

HERE = os.path.dirname(os.path.abspath(__file__))
SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
WYCHEPROOF_FILE = "/opt/wycheproof/testvectors_v1/aes_gcm_test.json"
WYCHEPROOF_CHACHA = "/opt/wycheproof/testvectors_v1/chacha20_poly1305_test.json"
WYCHEPROOF_X25519 = "/opt/wycheproof/testvectors_v1/x25519_test.json"
WYCHEPROOF_ED25519 = "/opt/wycheproof/testvectors_v1/ed25519_test.json"
WYCHEPROOF_ECDH_P256 = "/opt/wycheproof/testvectors_v1/ecdh_secp256r1_ecpoint_test.json"
WYCHEPROOF_ECDSA_P256 = "/opt/wycheproof/testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json"


def corpus_digest(filename):
    path = os.path.join(HERE, "containers", "CORPUS")
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            digest, name = line.split()
            if name == filename:
                return digest
    raise SystemExit("CORPUS has no digest for %s" % filename)


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
    want = corpus_digest("testvectors_v1/aes_gcm_test.json")
    if not compare.hex_equal(got, want):
        sys.stderr.write(
            "wycheproof aes_gcm_test.json is %s, CORPUS says %s\n" % (got, want))
        return 1
    print("wycheproof aes_gcm_test.json %s" % got)

    wy = subprocess.run(
        oracle_env.command("wycheproof", ["sha256sum", WYCHEPROOF_CHACHA]),
        capture_output=True)
    if wy.returncode != 0:
        sys.stderr.write(wy.stderr.decode("utf-8", "replace"))
        return 1
    fields = wy.stdout.decode("utf-8", "replace").split()
    if not fields:
        sys.stderr.write("sha256sum produced no digest\n")
        return 1
    got = fields[0]
    want = corpus_digest("testvectors_v1/chacha20_poly1305_test.json")
    if not compare.hex_equal(got, want):
        sys.stderr.write(
            "wycheproof chacha20_poly1305_test.json is %s, CORPUS says %s\n"
            % (got, want))
        return 1
    print("wycheproof chacha20_poly1305_test.json %s" % got)

    wy = subprocess.run(
        oracle_env.command("wycheproof", ["sha256sum", WYCHEPROOF_X25519]),
        capture_output=True)
    if wy.returncode != 0:
        sys.stderr.write(wy.stderr.decode("utf-8", "replace"))
        return 1
    fields = wy.stdout.decode("utf-8", "replace").split()
    if not fields:
        sys.stderr.write("sha256sum produced no digest\n")
        return 1
    got = fields[0]
    want = corpus_digest("testvectors_v1/x25519_test.json")
    if not compare.hex_equal(got, want):
        sys.stderr.write(
            "wycheproof x25519_test.json is %s, CORPUS says %s\n" % (got, want))
        return 1
    print("wycheproof x25519_test.json %s" % got)

    wy = subprocess.run(
        oracle_env.command("wycheproof", ["sha256sum", WYCHEPROOF_ED25519]),
        capture_output=True)
    if wy.returncode != 0:
        sys.stderr.write(wy.stderr.decode("utf-8", "replace"))
        return 1
    fields = wy.stdout.decode("utf-8", "replace").split()
    if not fields:
        sys.stderr.write("sha256sum produced no digest\n")
        return 1
    got = fields[0]
    want = corpus_digest("testvectors_v1/ed25519_test.json")
    if not compare.hex_equal(got, want):
        sys.stderr.write(
            "wycheproof ed25519_test.json is %s, CORPUS says %s\n" % (got, want))
        return 1
    print("wycheproof ed25519_test.json %s" % got)

    wy = subprocess.run(
        oracle_env.command("wycheproof", ["sha256sum", WYCHEPROOF_ECDH_P256]),
        capture_output=True)
    if wy.returncode != 0:
        sys.stderr.write(wy.stderr.decode("utf-8", "replace"))
        return 1
    fields = wy.stdout.decode("utf-8", "replace").split()
    if not fields:
        sys.stderr.write("sha256sum produced no digest\n")
        return 1
    got = fields[0]
    want = corpus_digest("testvectors_v1/ecdh_secp256r1_ecpoint_test.json")
    if not compare.hex_equal(got, want):
        sys.stderr.write(
            "wycheproof ecdh_secp256r1_ecpoint_test.json is %s, CORPUS says %s\n"
            % (got, want))
        return 1
    print("wycheproof ecdh_secp256r1_ecpoint_test.json %s" % got)
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
    return diff_aes()


def openssl_aes_block(bits, key_hex, block, decrypt):
    command = [
        "openssl", "enc", "-aes-%s-ecb" % bits, "-K", key_hex,
        "-nopad", "-nosalt"]
    if decrypt:
        command.append("-d")
    proc = subprocess.run(
        oracle_env.command("openssl", command),
        input=block, capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(1)
    if len(proc.stdout) != 16:
        sys.stderr.write("openssl aes wrote %s bytes\n" % len(proc.stdout))
        raise SystemExit(1)
    return proc.stdout.hex()


def library_aes_block(binary, direction, bits, key_hex, block_hex):
    proc = subprocess.run(
        [binary, direction, bits, key_hex, block_hex], capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        sys.stderr.write("aes helper exited %s\n" % proc.returncode)
        raise SystemExit(1)
    got = proc.stdout.decode("utf-8", "replace").strip()
    if len(got) != 32:
        sys.stderr.write("aes helper wrote %r\n" % got)
        raise SystemExit(1)
    return got


def diff_aes():
    binary = os.environ.get("GSEC_AES_BIN", "")
    if not binary:
        sys.stderr.write("GSEC_AES_BIN is not set\n")
        return 1
    cases = [
        ("128", "000102030405060708090a0b0c0d0e0f",
         bytes.fromhex("00112233445566778899aabbccddeeff")),
        ("192", "000102030405060708090a0b0c0d0e0f1011121314151617",
         bytes.fromhex("00112233445566778899aabbccddeeff")),
        ("256",
         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         bytes.fromhex("00112233445566778899aabbccddeeff")),
        ("128", "00" * 16, bytes(16)),
        ("256", "00" * 32, bytes(16)),
    ]
    for bits, key_hex, block in cases:
        want = openssl_aes_block(bits, key_hex, block, False)
        got = library_aes_block(binary, "encrypt", bits, key_hex, block.hex())
        if not compare.hex_equal(got, want):
            sys.stderr.write(
                "aes-%s encrypt is %s, openssl says %s\n" % (bits, got, want))
            return 1
        print("aes-%s encrypt %s" % (bits, want))
        back = openssl_aes_block(bits, key_hex, bytes.fromhex(want), True)
        got = library_aes_block(binary, "decrypt", bits, key_hex, want)
        if not compare.hex_equal(got, back):
            sys.stderr.write(
                "aes-%s decrypt is %s, openssl says %s\n" % (bits, got, back))
            return 1
        print("aes-%s decrypt %s" % (bits, back))
    return diff_ctr()


def openssl_aes_ctr(bits, key_hex, counter_hex, message):
    command = [
        "openssl", "enc", "-aes-%s-ctr" % bits, "-K", key_hex,
        "-iv", counter_hex, "-nosalt"]
    proc = subprocess.run(
        oracle_env.command("openssl", command),
        input=message, capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(1)
    if len(proc.stdout) != len(message):
        sys.stderr.write("openssl aes-ctr wrote %s bytes\n" % len(proc.stdout))
        raise SystemExit(1)
    return proc.stdout.hex()


def library_aes_ctr(binary, bits, key_hex, counter_hex, message):
    proc = subprocess.run(
        [binary, bits, "be", key_hex, counter_hex],
        input=message, capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        sys.stderr.write("aes-ctr helper exited %s\n" % proc.returncode)
        raise SystemExit(1)
    got = proc.stdout.decode("utf-8", "replace").strip()
    if len(got) != len(message) * 2:
        sys.stderr.write("aes-ctr helper wrote %r\n" % got)
        raise SystemExit(1)
    return got


def diff_ctr():
    binary = os.environ.get("GSEC_AES_CTR_BIN", "")
    if not binary:
        sys.stderr.write("GSEC_AES_CTR_BIN is not set\n")
        return 1
    cases = [
        ("128", "000102030405060708090a0b0c0d0e0f",
         "00000000000000000000000000000001", b"hello ctr mode!!"),
        ("128", "000102030405060708090a0b0c0d0e0f",
         "00000000000000000000000000000001", b"a" * 20),
        ("192", "000102030405060708090a0b0c0d0e0f1011121314151617",
         "00000000000000000000000000000001", b"a" * 20),
        ("256",
         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "00000000000000000000000000000000", b"ctr-256"),
    ]
    for bits, key_hex, counter_hex, message in cases:
        want = openssl_aes_ctr(bits, key_hex, counter_hex, message)
        got = library_aes_ctr(binary, bits, key_hex, counter_hex, message)
        if not compare.hex_equal(got, want):
            sys.stderr.write(
                "aes-%s-ctr is %s, openssl says %s\n" % (bits, got, want))
            return 1
        print("aes-%s-ctr %s" % (bits, want))
    return diff_gcm()


def same_hex(got, want):
    if got == "" and want == "":
        return True
    return compare.hex_equal(got, want)


def library_gcm(binary, direction, bits, key_hex, iv_hex, aad_hex, tag_hex,
        message):
    argv = [binary, direction, bits, key_hex, iv_hex, aad_hex]
    if direction == "decrypt":
        argv.append(tag_hex)
    proc = subprocess.run(argv, input=message, capture_output=True)
    text = proc.stdout.decode("utf-8", "replace")
    return proc.returncode, text


def diff_gcm():
    binary = os.environ.get("GSEC_AES_GCM_BIN", "")
    if not binary:
        sys.stderr.write("GSEC_AES_GCM_BIN is not set\n")
        return 1
    proc = subprocess.run(
        oracle_env.command("wycheproof", ["cat", WYCHEPROOF_FILE]),
        capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        return 1
    try:
        data = json.loads(proc.stdout.decode("utf-8"))
    except json.JSONDecodeError as error:
        sys.stderr.write("wycheproof aes_gcm_test.json: %s\n" % error)
        return 1
    checked = 0
    for group in data["testGroups"]:
        bits = str(group["keySize"])
        for case in group["tests"]:
            aad = case["aad"] if case["aad"] else "-"
            iv = case["iv"] if case["iv"] else "-"
            message = bytes.fromhex(case["msg"]) if case["msg"] else b""
            checked += 1
            if case["result"] != "valid":
                code, _text = library_gcm(
                    binary, "decrypt", bits, case["key"], iv, aad, case["tag"],
                    bytes.fromhex(case["ct"]) if case["ct"] else b"")
                if code == 0:
                    sys.stderr.write(
                        "aes-gcm tc %s was accepted\n" % case["tcId"])
                    return 1
                continue
            code, text = library_gcm(
                binary, "encrypt", bits, case["key"], iv, aad, "", message)
            lines = text.splitlines()
            if code != 0 or len(lines) != 2:
                sys.stderr.write(
                    "aes-gcm tc %s encrypt exited %s\n" % (case["tcId"], code))
                return 1
            if not same_hex(lines[0], case["ct"]) or not compare.hex_equal(
                    lines[1], case["tag"]):
                sys.stderr.write(
                    "aes-gcm tc %s encrypt is %s %s, wycheproof says %s %s\n"
                    % (case["tcId"], lines[0], lines[1], case["ct"], case["tag"]))
                return 1
            cipher = bytes.fromhex(case["ct"]) if case["ct"] else b""
            code, text = library_gcm(
                binary, "decrypt", bits, case["key"], iv, aad, case["tag"],
                cipher)
            if code != 0 or not same_hex(text.strip(), case["msg"]):
                sys.stderr.write(
                    "aes-gcm tc %s decrypt exited %s\n" % (case["tcId"], code))
                return 1
    if checked < 300:
        sys.stderr.write("aes-gcm checked %s wycheproof cases\n" % checked)
        return 1
    print("aes-gcm wycheproof %s" % checked)
    return diff_chacha()


def library_chacha(binary, direction, key_hex, nonce_hex, aad_hex, tag_hex,
        message):
    argv = [binary, direction, key_hex, nonce_hex, aad_hex]
    if direction == "decrypt":
        argv.append(tag_hex if tag_hex else "-")
    proc = subprocess.run(argv, input=message, capture_output=True)
    text = proc.stdout.decode("utf-8", "replace")
    return proc.returncode, text


def diff_chacha():
    binary = os.environ.get("GSEC_CHACHA20_POLY1305_BIN", "")
    if not binary:
        sys.stderr.write("GSEC_CHACHA20_POLY1305_BIN is not set\n")
        return 1
    proc = subprocess.run(
        oracle_env.command("wycheproof", ["cat", WYCHEPROOF_CHACHA]),
        capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        return 1
    try:
        data = json.loads(proc.stdout.decode("utf-8"))
    except json.JSONDecodeError as error:
        sys.stderr.write("wycheproof chacha20_poly1305_test.json: %s\n" % error)
        return 1
    checked = 0
    for group in data["testGroups"]:
        for case in group["tests"]:
            aad = case["aad"] if case["aad"] else "-"
            nonce = case["iv"] if case["iv"] else "-"
            message = bytes.fromhex(case["msg"]) if case["msg"] else b""
            checked += 1
            if case["result"] != "valid":
                code, _text = library_chacha(
                    binary, "decrypt", case["key"], nonce, aad, case["tag"],
                    bytes.fromhex(case["ct"]) if case["ct"] else b"")
                if code == 0:
                    sys.stderr.write(
                        "chacha20-poly1305 tc %s was accepted\n" % case["tcId"])
                    return 1
                continue
            code, text = library_chacha(
                binary, "encrypt", case["key"], nonce, aad, "", message)
            lines = text.splitlines()
            if code != 0 or len(lines) != 2:
                sys.stderr.write(
                    "chacha20-poly1305 tc %s encrypt exited %s\n"
                    % (case["tcId"], code))
                return 1
            if not same_hex(lines[0], case["ct"]) or not compare.hex_equal(
                    lines[1], case["tag"]):
                sys.stderr.write(
                    "chacha20-poly1305 tc %s encrypt is %s %s, wycheproof says %s %s\n"
                    % (case["tcId"], lines[0], lines[1], case["ct"], case["tag"]))
                return 1
            cipher = bytes.fromhex(case["ct"]) if case["ct"] else b""
            code, text = library_chacha(
                binary, "decrypt", case["key"], nonce, aad, case["tag"],
                cipher)
            if code != 0 or not same_hex(text.strip(), case["msg"]):
                sys.stderr.write(
                    "chacha20-poly1305 tc %s decrypt exited %s\n"
                    % (case["tcId"], code))
                return 1
    if checked < 320:
        sys.stderr.write(
            "chacha20-poly1305 checked %s wycheproof cases\n" % checked)
        return 1
    print("chacha20-poly1305 wycheproof %s" % checked)
    return diff_x25519()


def library_x25519(binary, scalar_hex, point_hex):
    proc = subprocess.run([binary, scalar_hex, point_hex], capture_output=True)
    text = proc.stdout.decode("utf-8", "replace")
    return proc.returncode, text


def diff_x25519():
    binary = os.environ.get("GSEC_X25519_BIN", "")
    if not binary:
        sys.stderr.write("GSEC_X25519_BIN is not set\n")
        return 1
    proc = subprocess.run(
        oracle_env.command("wycheproof", ["cat", WYCHEPROOF_X25519]),
        capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        return 1
    try:
        data = json.loads(proc.stdout.decode("utf-8"))
    except json.JSONDecodeError as error:
        sys.stderr.write("wycheproof x25519_test.json: %s\n" % error)
        return 1
    checked = 0
    for group in data["testGroups"]:
        for case in group["tests"]:
            checked += 1
            code, text = library_x25519(binary, case["private"], case["public"])
            shared = text.strip()
            if case["result"] == "valid":
                if code != 0 or not compare.hex_equal(shared, case["shared"]):
                    sys.stderr.write(
                        "x25519 tc %s exited %s\n" % (case["tcId"], code))
                    return 1
                continue
            if case["result"] == "acceptable":
                if code == 0 and not compare.hex_equal(shared, case["shared"]):
                    sys.stderr.write(
                        "x25519 tc %s accepted a different shared secret\n"
                        % case["tcId"])
                    return 1
                continue
            sys.stderr.write(
                "x25519 tc %s has result %s\n" % (case["tcId"], case["result"]))
            return 1
    if checked < 518:
        sys.stderr.write("x25519 checked %s wycheproof cases\n" % checked)
        return 1
    print("x25519 wycheproof %s" % checked)
    return diff_ed25519()


def library_ed25519(binary, pk_hex, sig_hex, msg_hex):
    message = msg_hex if msg_hex else "-"
    proc = subprocess.run(
        [binary, "verify", pk_hex, sig_hex, message], capture_output=True)
    return proc.returncode


def diff_ed25519():
    binary = os.environ.get("GSEC_ED25519_BIN", "")
    if not binary:
        sys.stderr.write("GSEC_ED25519_BIN is not set\n")
        return 1
    proc = subprocess.run(
        oracle_env.command("wycheproof", ["cat", WYCHEPROOF_ED25519]),
        capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        return 1
    try:
        data = json.loads(proc.stdout.decode("utf-8"))
    except json.JSONDecodeError as error:
        sys.stderr.write("wycheproof ed25519_test.json: %s\n" % error)
        return 1
    checked = 0
    for group in data["testGroups"]:
        pk = group["publicKey"]["pk"]
        for case in group["tests"]:
            checked += 1
            code = library_ed25519(binary, pk, case["sig"], case["msg"])
            if case["result"] == "valid":
                if code != 0:
                    sys.stderr.write(
                        "ed25519 tc %s exited %s\n" % (case["tcId"], code))
                    return 1
                continue
            if case["result"] == "invalid":
                if code == 0:
                    sys.stderr.write(
                        "ed25519 tc %s was accepted\n" % case["tcId"])
                    return 1
                continue
            sys.stderr.write(
                "ed25519 tc %s has result %s\n" % (case["tcId"], case["result"]))
            return 1
    if checked < 151:
        sys.stderr.write("ed25519 checked %s wycheproof cases\n" % checked)
        return 1
    print("ed25519 wycheproof %s" % checked)
    return diff_ecdh_p256()


def library_ecdh_p256(binary, scalar_hex, peer_hex):
    proc = subprocess.run(
        [binary, scalar_hex, peer_hex], capture_output=True)
    text = proc.stdout.decode("utf-8", "replace")
    return proc.returncode, text


def diff_ecdh_p256():
    binary = os.environ.get("GSEC_ECDH_P256_BIN", "")
    if not binary:
        sys.stderr.write("GSEC_ECDH_P256_BIN is not set\n")
        return 1
    proc = subprocess.run(
        oracle_env.command("wycheproof", ["cat", WYCHEPROOF_ECDH_P256]),
        capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        return 1
    try:
        data = json.loads(proc.stdout.decode("utf-8"))
    except json.JSONDecodeError as error:
        sys.stderr.write("wycheproof ecdh_secp256r1_ecpoint_test.json: %s\n" % error)
        return 1
    checked = 0
    for group in data["testGroups"]:
        for case in group["tests"]:
            checked += 1
            code, text = library_ecdh_p256(binary, case["private"], case["public"])
            shared = text.strip()
            if case["result"] == "valid":
                if code != 0 or not compare.hex_equal(shared, case["shared"]):
                    sys.stderr.write(
                        "ecdh-p256 tc %s exited %s\n" % (case["tcId"], code))
                    return 1
                continue
            if case["result"] == "invalid" or case["result"] == "acceptable":
                if code == 0:
                    sys.stderr.write(
                        "ecdh-p256 tc %s was accepted\n" % case["tcId"])
                    return 1
                continue
            sys.stderr.write(
                "ecdh-p256 tc %s has result %s\n" % (case["tcId"], case["result"]))
            return 1
    if checked < 355:
        sys.stderr.write("ecdh-p256 checked %s wycheproof cases\n" % checked)
        return 1
    print("ecdh-p256 wycheproof %s" % checked)
    return diff_ecdsa_p256()


def library_ecdsa_p256(binary, pub_hex, msg_hex, sig_hex):
    message = msg_hex if msg_hex else "-"
    proc = subprocess.run(
        [binary, "verify", pub_hex, message, sig_hex], capture_output=True)
    return proc.returncode


def diff_ecdsa_p256():
    binary = os.environ.get("GSEC_ECDSA_P256_BIN", "")
    if not binary:
        sys.stderr.write("GSEC_ECDSA_P256_BIN is not set\n")
        return 1
    proc = subprocess.run(
        oracle_env.command("wycheproof", ["cat", WYCHEPROOF_ECDSA_P256]),
        capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        return 1
    try:
        data = json.loads(proc.stdout.decode("utf-8"))
    except json.JSONDecodeError as error:
        sys.stderr.write(
            "wycheproof ecdsa_secp256r1_sha256_p1363_test.json: %s\n" % error)
        return 1
    checked = 0
    for group in data["testGroups"]:
        pub = group["publicKey"]["uncompressed"]
        for case in group["tests"]:
            checked += 1
            code = library_ecdsa_p256(binary, pub, case["msg"], case["sig"])
            if case["result"] == "valid":
                if code != 0:
                    sys.stderr.write(
                        "ecdsa-p256 tc %s exited %s\n" % (case["tcId"], code))
                    return 1
                continue
            if case["result"] == "invalid":
                if code == 0:
                    sys.stderr.write(
                        "ecdsa-p256 tc %s was accepted\n" % case["tcId"])
                    return 1
                continue
            sys.stderr.write(
                "ecdsa-p256 tc %s has result %s\n" % (case["tcId"], case["result"]))
            return 1
    if checked < 262:
        sys.stderr.write("ecdsa-p256 checked %s wycheproof cases\n" % checked)
        return 1
    print("ecdsa-p256 wycheproof %s" % checked)
    return diff_rsa()


HASH_NAME = {
    "SHA-1": "sha1",
    "SHA-256": "sha256",
    "SHA-384": "sha384",
    "SHA-512": "sha512",
    "MD5": "md5",
}

PKCS1_FILES = (
    ("rsa_signature_2048_sha256_test.json", 259),
    ("rsa_signature_2048_sha384_test.json", 258),
    ("rsa_signature_2048_sha512_test.json", 259),
    ("rsa_signature_3072_sha256_test.json", 259),
    ("rsa_signature_3072_sha384_test.json", 259),
    ("rsa_signature_3072_sha512_test.json", 260),
    ("rsa_signature_4096_sha256_test.json", 258),
    ("rsa_signature_4096_sha512_test.json", 259),
)

PSS_FILES = (
    ("rsa_pss_2048_sha256_mgf1_32_test.json", 108),
    ("rsa_pss_2048_sha256_mgf1_0_test.json", 103),
    ("rsa_pss_2048_sha384_mgf1_48_test.json", 141),
    ("rsa_pss_2048_sha1_mgf1_20_test.json", 88),
    ("rsa_pss_2048_sha256_mgf1sha1_20_test.json", 108),
    ("rsa_pss_3072_sha256_mgf1_32_test.json", 108),
    ("rsa_pss_4096_sha256_mgf1_32_test.json", 108),
    ("rsa_pss_4096_sha512_mgf1_64_test.json", 179),
)


def library_rsa_pkcs1(binary, hash_name, n_hex, e_hex, msg_hex, sig_hex):
    message = msg_hex if msg_hex else "-"
    proc = subprocess.run(
        [binary, "pkcs1", hash_name, n_hex, e_hex, message, sig_hex],
        capture_output=True)
    return proc.returncode


def library_rsa_pss(binary, hash_name, mgf_name, salt, n_hex, e_hex, msg_hex,
        sig_hex):
    message = msg_hex if msg_hex else "-"
    proc = subprocess.run(
        [binary, "pss", hash_name, mgf_name, str(salt), n_hex, e_hex, message,
         sig_hex],
        capture_output=True)
    return proc.returncode


def load_wycheproof(name):
    path = "/opt/wycheproof/testvectors_v1/" + name
    proc = subprocess.run(
        oracle_env.command("wycheproof", ["cat", path]), capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        return None
    try:
        return json.loads(proc.stdout.decode("utf-8"))
    except json.JSONDecodeError as error:
        sys.stderr.write("wycheproof %s: %s\n" % (name, error))
        return None


def diff_rsa():
    binary = os.environ.get("GSEC_RSA_BIN", "")
    if not binary:
        sys.stderr.write("GSEC_RSA_BIN is not set\n")
        return 1
    for name, minimum in PKCS1_FILES:
        data = load_wycheproof(name)
        if data is None:
            return 1
        checked = 0
        for group in data["testGroups"]:
            hash_name = HASH_NAME.get(group["sha"])
            if hash_name is None:
                sys.stderr.write("%s has hash %s\n" % (name, group["sha"]))
                return 1
            n_hex = group["publicKey"]["modulus"]
            e_hex = group["publicKey"]["publicExponent"]
            for case in group["tests"]:
                checked += 1
                code = library_rsa_pkcs1(
                    binary, hash_name, n_hex, e_hex, case["msg"], case["sig"])
                if case["result"] == "valid":
                    if code != 0:
                        sys.stderr.write(
                            "rsa-pkcs1 %s tc %s exited %s\n"
                            % (name, case["tcId"], code))
                        return 1
                    continue
                if case["result"] == "invalid" or case["result"] == "acceptable":
                    if code == 0:
                        sys.stderr.write(
                            "rsa-pkcs1 %s tc %s was accepted\n"
                            % (name, case["tcId"]))
                        return 1
                    continue
                sys.stderr.write(
                    "rsa-pkcs1 %s tc %s has result %s\n"
                    % (name, case["tcId"], case["result"]))
                return 1
        if checked < minimum:
            sys.stderr.write("rsa-pkcs1 %s checked %s\n" % (name, checked))
            return 1
        print("rsa-pkcs1 %s %s" % (name, checked))
    for name, minimum in PSS_FILES:
        data = load_wycheproof(name)
        if data is None:
            return 1
        checked = 0
        for group in data["testGroups"]:
            hash_name = HASH_NAME.get(group["sha"])
            mgf_name = HASH_NAME.get(group["mgfSha"])
            if hash_name is None or mgf_name is None:
                sys.stderr.write("%s has hash %s mgf %s\n"
                    % (name, group.get("sha"), group.get("mgfSha")))
                return 1
            n_hex = group["publicKey"]["modulus"]
            e_hex = group["publicKey"]["publicExponent"]
            salt = group["sLen"]
            for case in group["tests"]:
                checked += 1
                code = library_rsa_pss(
                    binary, hash_name, mgf_name, salt, n_hex, e_hex,
                    case["msg"], case["sig"])
                if case["result"] == "valid":
                    if code != 0:
                        sys.stderr.write(
                            "rsa-pss %s tc %s exited %s\n"
                            % (name, case["tcId"], code))
                        return 1
                    continue
                if case["result"] == "invalid" or case["result"] == "acceptable":
                    if code == 0:
                        sys.stderr.write(
                            "rsa-pss %s tc %s was accepted\n" % (name, case["tcId"]))
                        return 1
                    continue
                sys.stderr.write(
                    "rsa-pss %s tc %s has result %s\n"
                    % (name, case["tcId"], case["result"]))
                return 1
        if checked < minimum:
            sys.stderr.write("rsa-pss %s checked %s\n" % (name, checked))
            return 1
        print("rsa-pss %s %s" % (name, checked))
    return diff_rsa_sign()


def rsa_text_block(text, label):
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not line.startswith(label):
            continue
        rest = line.split(":", 1)[1].strip()
        if "0x" in rest:
            found = re.search(r"0x([0-9a-fA-F]+)", rest)
            if found is None:
                return None
            hex_text = found.group(1)
        else:
            chunks = []
            cursor = index + 1
            while cursor < len(lines) and (lines[cursor].startswith(" ")
                    or lines[cursor].startswith("\t")):
                chunks.append(lines[cursor].strip().replace(":", ""))
                cursor += 1
            hex_text = "".join(chunks)
        if len(hex_text) % 2:
            hex_text = "0" + hex_text
        if not hex_text:
            return None
        return hex_text
    return None


def diff_rsa_sign():
    """Sign with this library and ask the pinned OpenSSL to verify.

    A round trip through our own verifier would share a bug. The key is
    generated in the image, so the signature is not one of the known answers.
    """
    binary = os.environ.get("GSEC_RSA_BIN", "")
    if not binary:
        sys.stderr.write("GSEC_RSA_BIN is not set\n")
        return 1
    scratch = tempfile.mkdtemp(prefix="gsec-rsa-sign-")
    try:
        key = os.path.join(scratch, "key.pem")
        msg_path = os.path.join(scratch, "msg")
        sig_path = os.path.join(scratch, "sig")
        with open(msg_path, "wb") as handle:
            handle.write(b"sample")
        made = subprocess.run(oracle_env.command("openssl", [
            "openssl", "genpkey", "-algorithm", "RSA",
            "-pkeyopt", "rsa_keygen_bits:2048", "-out", key,
        ], scratch=scratch), capture_output=True)
        if made.returncode != 0:
            sys.stderr.write(made.stderr.decode("utf-8", "replace"))
            return 1
        shown = subprocess.run(oracle_env.command("openssl", [
            "openssl", "pkey", "-in", key, "-noout", "-text",
        ], scratch=scratch), capture_output=True)
        if shown.returncode != 0:
            sys.stderr.write(shown.stderr.decode("utf-8", "replace"))
            return 1
        text = shown.stdout.decode("utf-8", "replace")
        modulus = rsa_text_block(text, "modulus")
        public = rsa_text_block(text, "publicExponent")
        private = rsa_text_block(text, "privateExponent")
        if modulus is None or public is None or private is None:
            sys.stderr.write("openssl did not print an RSA key\n")
            return 1
        message = "73616d706c65"
        signed = subprocess.run(
            [binary, "sign-pkcs1", "sha256", modulus, public, private, message],
            capture_output=True, text=True)
        if signed.returncode != 0 or not signed.stdout.strip():
            sys.stderr.write("rsa sign-pkcs1 exited %s\n" % signed.returncode)
            return 1
        with open(sig_path, "wb") as handle:
            handle.write(bytes.fromhex(signed.stdout.strip()))
        checked = subprocess.run(oracle_env.command("openssl", [
            "openssl", "dgst", "-sha256", "-verify", key,
            "-signature", sig_path, msg_path,
        ], scratch=scratch), capture_output=True, text=True)
        if checked.returncode != 0:
            sys.stderr.write(checked.stderr)
            sys.stderr.write("openssl rejected the PKCS#1 signature\n")
            return 1
        salt = "11" * 32
        signed = subprocess.run(
            [binary, "sign-pss", "sha256", "sha256", salt, modulus, public,
             private, message],
            capture_output=True, text=True)
        if signed.returncode != 0 or not signed.stdout.strip():
            sys.stderr.write("rsa sign-pss exited %s\n" % signed.returncode)
            return 1
        with open(sig_path, "wb") as handle:
            handle.write(bytes.fromhex(signed.stdout.strip()))
        checked = subprocess.run(oracle_env.command("openssl", [
            "openssl", "pkeyutl", "-verify", "-inkey", key, "-in", msg_path,
            "-rawin", "-digest", "sha256", "-sigfile", sig_path,
            "-pkeyopt", "rsa_padding_mode:pss",
            "-pkeyopt", "rsa_pss_saltlen:32",
        ], scratch=scratch), capture_output=True, text=True)
        if checked.returncode != 0:
            sys.stderr.write(checked.stderr)
            sys.stderr.write("openssl rejected the PSS signature\n")
            return 1
        print("rsa-sign pkcs1 sha256")
        print("rsa-sign pss sha256")
        return diff_cbc()
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def openssl_aes_cbc(bits, key_hex, iv_hex, message, decrypt):
    command = [
        "openssl", "enc", "-aes-%s-cbc" % bits, "-K", key_hex, "-iv", iv_hex,
        "-nopad", "-nosalt"]
    if decrypt:
        command.append("-d")
    proc = subprocess.run(
        oracle_env.command("openssl", command),
        input=message, capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(1)
    return proc.stdout.hex()


def library_aes_cbc(binary, direction, bits, key_hex, iv_hex, message_hex):
    proc = subprocess.run(
        [binary, direction, bits, key_hex, iv_hex, message_hex],
        capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        sys.stderr.write("aes-cbc helper exited %s\n" % proc.returncode)
        raise SystemExit(1)
    return proc.stdout.strip()


def diff_cbc():
    binary = os.environ["GSEC_AES_CBC_BIN"]
    cases = [
        ("128", "000102030405060708090a0b0c0d0e0f",
         "00000000000000000000000000000001",
         bytes.fromhex("68656c6c6f20636263206d6f64652121")),
        ("256",
         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "0f0e0d0c0b0a09080706050403020100",
         bytes.fromhex("61" * 32)),
        ("128", "00" * 16, "00" * 16, b""),
    ]
    for bits, key, iv, message in cases:
        want = openssl_aes_cbc(bits, key, iv, message, False)
        got = library_aes_cbc(binary, "encrypt", bits, key, iv, message.hex())
        if not compare.hex_equal(got, want):
            sys.stderr.write("aes-cbc %s encrypt is %s, openssl says %s\n"
                % (bits, got, want))
            return 1
        back = library_aes_cbc(binary, "decrypt", bits, key, iv, got)
        if not compare.hex_equal(back, message.hex()):
            sys.stderr.write("aes-cbc %s decrypt is %s\n" % (bits, back))
            return 1
        print("aes-cbc %s %s" % (bits, want))
    return diff_des()


def openssl_des(mode, key_hex, iv_hex, message):
    flag = {
        "ecb": "-des-ecb",
        "cbc": "-des-cbc",
        "ede3": "-des-ede3",
    }[mode]
    command = [
        "openssl", "enc", "-provider", "legacy", "-provider", "default",
        flag, "-K", key_hex, "-nopad", "-nosalt"]
    if iv_hex is not None:
        command.extend(["-iv", iv_hex])
    proc = subprocess.run(
        oracle_env.command("openssl", command),
        input=message, capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(1)
    return proc.stdout.hex()


def library_des(binary, mode, direction, key_hex, iv_hex, message_hex):
    proc = subprocess.run(
        [binary, mode, direction, key_hex, iv_hex, message_hex],
        capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        sys.stderr.write("des helper exited %s\n" % proc.returncode)
        raise SystemExit(1)
    return proc.stdout.strip()


def diff_des():
    binary = os.environ["GSEC_DES_BIN"]
    cases = [
        ("ecb", "133457799bbcdff1", "-",
         bytes.fromhex("0123456789abcdef")),
        ("cbc", "133457799bbcdff1", "0000000000000000",
         bytes.fromhex("0123456789abcdef" * 2)),
        ("ede3", "0123456789abcdef5555555555555555fedcba9876543210", "-",
         bytes.fromhex("0123456789abcdef")),
    ]
    for mode, key, iv, message in cases:
        iv_arg = None if iv == "-" else iv
        want = openssl_des(mode, key, iv_arg, message)
        got = library_des(binary, mode, "encrypt", key, iv, message.hex())
        if not compare.hex_equal(got, want):
            sys.stderr.write("des %s is %s, openssl says %s\n" % (mode, got, want))
            return 1
        print("des %s %s" % (mode, want))
    return diff_rc4()


def openssl_rc4(key_hex, message):
    command = [
        "openssl", "enc", "-provider", "legacy", "-provider", "default",
        "-rc4", "-K", key_hex, "-nopad", "-nosalt"]
    proc = subprocess.run(
        oracle_env.command("openssl", command),
        input=message, capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(1)
    return proc.stdout.hex()


def library_rc4(binary, key_hex, message_hex):
    proc = subprocess.run(
        [binary, key_hex, message_hex], capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(1)
    return proc.stdout.strip()


def diff_rc4():
    binary = os.environ["GSEC_RC4_BIN"]
    message = bytes.fromhex("61" * 16)
    key = "0102030405060708090a0b0c0d0e0f10"
    want = openssl_rc4(key, message)
    got = library_rc4(binary, key, message.hex())
    if not compare.hex_equal(got, want):
        sys.stderr.write("rc4 is %s, openssl says %s\n" % (got, want))
        return 1
    print("rc4 %s" % want)
    return 0


if __name__ == "__main__":
    sys.exit(main())
