#!/usr/bin/env python3
"""Verify an agentcomms wheel without installing, importing, or extracting it."""

import argparse
import hashlib
import json
import stat
import sys
import zipfile
from pathlib import Path


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def verify(wheel_path, manifest_path):
    wheel_path = Path(wheel_path)
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    expected_distribution = manifest["distribution"]
    expected_files = {item["path"]: item for item in manifest["files"]}
    wheel_bytes = wheel_path.read_bytes()
    errors = []

    if wheel_path.name != expected_distribution["filename"]:
        errors.append("wheel filename does not match manifest")
    if len(wheel_bytes) != expected_distribution["size"]:
        errors.append("wheel size does not match manifest")
    if _sha256(wheel_bytes) != expected_distribution["sha256"]:
        errors.append("wheel SHA-256 does not match manifest")

    with zipfile.ZipFile(wheel_path) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            errors.append("wheel contains duplicate paths")
        actual_files = {info.filename for info in infos if not info.is_dir()}
        if actual_files != set(expected_files):
            errors.append("wheel file set does not match manifest")
        for info in infos:
            if info.is_dir() or info.filename not in expected_files:
                continue
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                errors.append(f"symbolic link is not allowed: {info.filename}")
                continue
            expected = expected_files[info.filename]
            if info.file_size != expected["size"]:
                errors.append(f"size mismatch: {info.filename}")
                continue
            with archive.open(info, "r") as member:
                digest = hashlib.sha256()
                remaining = expected["size"]
                while remaining:
                    chunk = member.read(min(65536, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    digest.update(chunk)
                if remaining or member.read(1):
                    errors.append(f"stream length mismatch: {info.filename}")
                elif digest.hexdigest() != expected["sha256"]:
                    errors.append(f"SHA-256 mismatch: {info.filename}")

    return {
        "schema": "agentcomms-wheel-verification-v1",
        "verified": not errors,
        "wheel": wheel_path.name,
        "wheelSha256": _sha256(wheel_bytes),
        "filesChecked": len(expected_files),
        "errors": errors,
        "authorityUsed": {
            "packageInstall": False,
            "packageImport": False,
            "network": False,
            "filesystemWrite": False,
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", help="local wheel file to inspect")
    parser.add_argument("manifest", help="local PACKAGE_MANIFEST_V2.json")
    args = parser.parse_args(argv)
    try:
        result = verify(args.wheel, args.manifest)
    except (OSError, KeyError, TypeError, ValueError, zipfile.BadZipFile) as exc:
        result = {
            "schema": "agentcomms-wheel-verification-v1",
            "verified": False,
            "errors": [f"{type(exc).__name__}: {exc}"],
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
