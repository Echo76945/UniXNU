#!/usr/bin/env python3
"""Pack, verify, or unpack the encrypted Muyu payload input bundle.

The release asset is public only as ciphertext. The passphrase stays in an
environment variable and is passed to OpenSSL through stdin, never argv.
"""

import argparse
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

EXPECTED_TRUST_SHA256 = "dc655bcb2ddfaea214f9ec83659b3fc8d8b658bafac2b5a004fb4179a25c89bf"
PBKDF2_ITERATIONS = 600_000
MAC_FORMAT = "muyu-input-bundle-hmac-v1"
MAC_SALT_BYTES = 32
TRUST_NAME = "trustcache"
DATA_NAME = "data.dbr"
MANIFEST_NAME = "manifest.json"
ALLOWED_MEMBERS = {TRUST_NAME, DATA_NAME, MANIFEST_NAME}
DATA_MAGIC = b"DBRDISK1"
MAX_DATA_BYTES = 256 * 1024**2
MAX_BUNDLE_BYTES = 320 * 1024**2
MAX_HMAC_BYTES = 4 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_TRUST_BYTES = 1 * 1024**2
MEMBER_LIMITS = {
    TRUST_NAME: MAX_TRUST_BYTES,
    DATA_NAME: MAX_DATA_BYTES,
    MANIFEST_NAME: MAX_MANIFEST_BYTES,
}
RELEASE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


def fail(message):
    raise SystemExit(message)


def validate_release_name(value, label):
    if not value or not RELEASE_NAME.fullmatch(value):
        fail(f"{label} contains unsupported characters")


def passphrase_from_env(name):
    value = os.environ.get(name)
    if not value:
        fail(f"{name} is not set")
    if "\n" in value or "\r" in value:
        fail(f"{name} must be a single line")
    return value.encode("utf-8")


def file_sha256(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        for block in iter(lambda: source.read(8 << 20), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def validate_data_seed(path):
    size = path.stat().st_size
    if size < 32 or size > MAX_DATA_BYTES:
        fail("Data seed is empty, truncated, or larger than the packed format limit")
    with path.open("rb") as source:
        header = source.read(32)
    magic, version, page, logical, count = struct.unpack("<8sIIQQ", header)
    if (magic != DATA_MAGIC or version != 1 or page != 4096 or
            not 0 < logical <= 1024**4 or logical % page or count > 65536):
        fail("Data seed is not a valid DBRDISK1 packed image")
    if size < 32 + 16 * count:
        fail("Data seed extent table is truncated")


def mac_key(passphrase, salt):
    # A per-bundle salt keeps the public HMAC file from becoming a cheap
    # offline passphrase verifier.
    return hashlib.pbkdf2_hmac(
        "sha256", passphrase, salt, PBKDF2_ITERATIONS, dklen=32
    )


def mac_metadata(asset, release_tag, salt):
    return (
        f"{MAC_FORMAT}\n"
        f"asset={asset}\n"
        f"release_tag={release_tag}\n"
        f"salt={salt.hex()}\n"
    ).encode("ascii")


def bundle_hmac(path, passphrase, asset, release_tag, salt):
    digest = hmac.new(mac_key(passphrase, salt), digestmod=hashlib.sha256)
    digest.update(mac_metadata(asset, release_tag, salt))
    with path.open("rb") as source:
        for block in iter(lambda: source.read(8 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def read_hmac_file(path):
    if path.stat().st_size > MAX_HMAC_BYTES:
        fail("the encrypted input bundle HMAC file is too large")
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        fail("the encrypted input bundle HMAC file is invalid")
    if not lines or lines[0] != MAC_FORMAT:
        fail("the encrypted input bundle HMAC file is invalid")
    fields = {}
    for line in lines[1:]:
        key, separator, value = line.partition("=")
        if not separator or key in fields:
            fail("the encrypted input bundle HMAC file is invalid")
        fields[key] = value
    if set(fields) != {"asset", "release_tag", "salt", "tag"}:
        fail("the encrypted input bundle HMAC file is invalid")
    validate_release_name(fields["asset"], "encrypted input bundle asset name")
    validate_release_name(fields["release_tag"], "encrypted input bundle release tag")
    try:
        salt = bytes.fromhex(fields["salt"])
    except ValueError:
        fail("the encrypted input bundle HMAC file is invalid")
    if len(salt) != MAC_SALT_BYTES or len(fields["tag"]) != 64:
        fail("the encrypted input bundle HMAC file is invalid")
    if any(char not in "0123456789abcdefABCDEF" for char in fields["tag"]):
        fail("the encrypted input bundle HMAC file is invalid")
    return {
        "asset": fields["asset"],
        "release_tag": fields["release_tag"],
        "salt": salt,
        "tag": fields["tag"].lower(),
    }


def verify_hmac(bundle, hmac_path, passphrase, expected_asset="", expected_tag=""):
    record = read_hmac_file(hmac_path)
    if expected_asset and record["asset"] != expected_asset:
        fail("encrypted input bundle asset name does not match")
    if expected_tag and record["release_tag"] != expected_tag:
        fail("encrypted input bundle release tag does not match")
    actual = bundle_hmac(
        bundle,
        passphrase,
        record["asset"],
        record["release_tag"],
        record["salt"],
    )
    if not hmac.compare_digest(actual, record["tag"]):
        fail("the encrypted input bundle HMAC does not match")
    return record


def run_openssl(openssl, mode, source, target, passphrase):
    command = [
        openssl,
        "enc",
        f"-{mode}",
        "-aes-256-cbc",
        "-pbkdf2",
        "-iter",
        str(PBKDF2_ITERATIONS),
        "-md",
        "sha256",
        "-pass",
        "stdin",
        "-in",
        str(source),
        "-out",
        str(target),
    ]
    if mode == "e":
        command.insert(5, "-salt")
    try:
        result = subprocess.run(
            command,
            input=passphrase + b"\n",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError:
        fail(f"OpenSSL executable not found: {openssl}")
    if result.returncode:
        fail(f"OpenSSL failed while trying to {mode} the input bundle")


def add_file(archive, path, arcname):
    info = archive.gettarinfo(str(path), arcname=arcname)
    info.mode = 0o600
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    with path.open("rb") as source:
        archive.addfile(info, source)


def pack(args):
    trust = args.trust_cache.resolve()
    data = args.data_seed.resolve()
    output = args.output.resolve()
    validate_release_name(output.name, "output asset name")
    validate_release_name(args.release_tag, "release tag")
    for path in (trust, data):
        if not path.is_file() or path.stat().st_size == 0:
            fail(f"input is missing or empty: {path}")
    if trust.stat().st_size > MAX_TRUST_BYTES:
        fail("trust cache is larger than the allowed bundle member size")
    validate_data_seed(data)

    trust_sha256, trust_bytes = file_sha256(trust)
    if trust_sha256 != EXPECTED_TRUST_SHA256:
        fail("trust cache SHA-256 does not match the expected 24A446 bundle")
    data_sha256, data_bytes = file_sha256(data)
    passphrase = passphrase_from_env(args.passphrase_env)

    output.parent.mkdir(parents=True, exist_ok=True)
    hmac_output = output.with_name(output.name + ".hmac")
    if output.exists() or hmac_output.exists():
        fail("refusing to overwrite an existing encrypted input bundle")
    salt = os.urandom(MAC_SALT_BYTES)
    with tempfile.TemporaryDirectory(prefix="muyu-input-pack-", dir=output.parent) as scratch:
        scratch = Path(scratch)
        plain = scratch / "muyu-inputs.tar.gz"
        manifest = {
            "schema": 1,
            "kind": "muyu-ipados27-input-bundle",
            "asset": output.name,
            "release_tag": args.release_tag,
            "trust_cache_sha256": trust_sha256,
            "trust_cache_bytes": trust_bytes,
            "data_seed_sha256": data_sha256,
            "data_seed_bytes": data_bytes,
        }
        manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        with tarfile.open(plain, "w:gz", compresslevel=6, format=tarfile.PAX_FORMAT) as archive:
            add_file(archive, trust, TRUST_NAME)
            add_file(archive, data, DATA_NAME)
            info = tarfile.TarInfo(MANIFEST_NAME)
            info.size = len(manifest_bytes)
            info.mode = 0o600
            info.mtime = 0
            archive.addfile(info, io.BytesIO(manifest_bytes))
        plain.chmod(0o600)

        encrypted = scratch / output.name
        run_openssl(args.openssl, "e", plain, encrypted, passphrase)
        hmac_value = bundle_hmac(
            encrypted, passphrase, output.name, args.release_tag, salt
        )
        staged_hmac = scratch / (output.name + ".hmac")
        staged_hmac.write_text(
            f"{MAC_FORMAT}\n"
            f"asset={output.name}\n"
            f"release_tag={args.release_tag}\n"
            f"salt={salt.hex()}\n"
            f"tag={hmac_value}\n",
            encoding="ascii",
        )
        shutil.move(str(encrypted), output)
        shutil.move(str(staged_hmac), hmac_output)
        output.chmod(0o600)
        hmac_output.chmod(0o600)

    print(f"wrote encrypted input bundle: {output}")
    print(f"wrote HMAC: {hmac_output}")


def verify(args):
    bundle = args.bundle.resolve()
    hmac_path = args.hmac.resolve()
    if not bundle.is_file() or not hmac_path.is_file():
        fail("the encrypted input bundle or HMAC file is missing")
    if bundle.stat().st_size > MAX_BUNDLE_BYTES:
        fail("the encrypted input bundle is too large")
    passphrase = passphrase_from_env(args.passphrase_env)
    verify_hmac(
        bundle,
        hmac_path,
        passphrase,
        expected_asset=args.expected_asset,
        expected_tag=args.expected_tag,
    )
    print("encrypted input bundle HMAC verified")


def unpack(args):
    bundle = args.bundle.resolve()
    hmac_path = args.hmac.resolve()
    output = args.output_dir.resolve()
    if not bundle.is_file() or not hmac_path.is_file():
        fail("the encrypted input bundle or HMAC file is missing")
    if bundle.stat().st_size > MAX_BUNDLE_BYTES:
        fail("the encrypted input bundle is too large")
    if output.exists() and any(output.iterdir()):
        fail(f"refusing to overwrite a non-empty directory: {output}")
    output.mkdir(parents=True, exist_ok=True)
    output.chmod(0o700)
    passphrase = passphrase_from_env(args.passphrase_env)
    record = verify_hmac(
        bundle,
        hmac_path,
        passphrase,
        expected_asset=args.expected_asset,
        expected_tag=args.expected_tag,
    )

    with tempfile.TemporaryDirectory(prefix="muyu-input-unpack-", dir=output.parent) as scratch:
        scratch = Path(scratch)
        plain = scratch / "muyu-inputs.tar.gz"
        run_openssl(args.openssl, "d", bundle, plain, passphrase)
        if plain.stat().st_size > MAX_BUNDLE_BYTES:
            fail("the decrypted input bundle is too large")
        extracted = scratch / "files"
        extracted.mkdir()
        seen = set()
        total = 0
        with tarfile.open(plain, "r:gz") as archive:
            for member in archive:
                if member.name not in ALLOWED_MEMBERS or not member.isfile() or member.name in seen:
                    fail(f"unexpected member in encrypted input bundle: {member.name}")
                if member.size > MEMBER_LIMITS[member.name]:
                    fail(f"member in encrypted input bundle is too large: {member.name}")
                total += member.size
                if total > sum(MEMBER_LIMITS.values()):
                    fail("encrypted input bundle expands beyond the allowed size")
                seen.add(member.name)
                source = archive.extractfile(member)
                if source is None:
                    fail(f"cannot read member in encrypted input bundle: {member.name}")
                target = extracted / member.name
                with source, target.open("wb") as destination:
                    shutil.copyfileobj(source, destination, 8 << 20)
                target.chmod(0o600)
        if seen != ALLOWED_MEMBERS:
            fail("encrypted input bundle is incomplete")

        manifest = json.loads((extracted / MANIFEST_NAME).read_text(encoding="utf-8"))
        if manifest.get("schema") != 1 or manifest.get("kind") != "muyu-ipados27-input-bundle":
            fail("encrypted input bundle manifest is invalid")
        if (manifest.get("asset"), manifest.get("release_tag")) != (
            record["asset"],
            record["release_tag"],
        ):
            fail("encrypted input bundle manifest asset or release tag does not match")
        trust_sha256, trust_bytes = file_sha256(extracted / TRUST_NAME)
        data_sha256, data_bytes = file_sha256(extracted / DATA_NAME)
        validate_data_seed(extracted / DATA_NAME)
        if trust_sha256 != EXPECTED_TRUST_SHA256:
            fail("trust cache SHA-256 does not match the expected 24A446 bundle")
        if (trust_sha256, trust_bytes) != (
            manifest.get("trust_cache_sha256"),
            manifest.get("trust_cache_bytes"),
        ):
            fail("trust cache does not match the encrypted input bundle manifest")
        if (data_sha256, data_bytes) != (
            manifest.get("data_seed_sha256"),
            manifest.get("data_seed_bytes"),
        ):
            fail("Data seed does not match the encrypted input bundle manifest")

        for name in (TRUST_NAME, DATA_NAME):
            shutil.move(str(extracted / name), output / name)
    print("encrypted input bundle verified and unpacked")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    pack_parser = subparsers.add_parser("pack", help="create the encrypted release asset")
    pack_parser.add_argument("--trust-cache", type=Path, required=True)
    pack_parser.add_argument("--data-seed", type=Path, required=True)
    pack_parser.add_argument("--output", type=Path, required=True)
    pack_parser.add_argument("--release-tag", default="muyu-ipados27-inputs")
    pack_parser.add_argument("--passphrase-env", default="MUYU_DATA_SEED_PASSPHRASE")
    pack_parser.add_argument("--openssl", default="openssl")
    pack_parser.set_defaults(func=pack)

    verify_parser = subparsers.add_parser("verify", help="verify the encrypted asset HMAC")
    verify_parser.add_argument("--bundle", type=Path, required=True)
    verify_parser.add_argument("--hmac", type=Path, required=True)
    verify_parser.add_argument("--expected-asset", default="")
    verify_parser.add_argument("--expected-tag", default="")
    verify_parser.add_argument("--passphrase-env", default="MUYU_DATA_SEED_PASSPHRASE")
    verify_parser.set_defaults(func=verify)

    unpack_parser = subparsers.add_parser("unpack", help="verify and unpack the encrypted asset")
    unpack_parser.add_argument("--bundle", type=Path, required=True)
    unpack_parser.add_argument("--hmac", type=Path, required=True)
    unpack_parser.add_argument("--output-dir", type=Path, required=True)
    unpack_parser.add_argument("--expected-asset", default="")
    unpack_parser.add_argument("--expected-tag", default="")
    unpack_parser.add_argument("--passphrase-env", default="MUYU_DATA_SEED_PASSPHRASE")
    unpack_parser.add_argument("--openssl", default="openssl")
    unpack_parser.set_defaults(func=unpack)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
