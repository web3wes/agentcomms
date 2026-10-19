"""Build a deterministic, wheel-derived package transparency manifest."""

import argparse
import configparser
import hashlib
import json
import pathlib
import zipfile
from email.parser import BytesParser

NATIVE_SUFFIXES = (".dll", ".dylib", ".exe", ".pyd", ".so")
DEFAULT_HUB_HOST = "web3wes.pythonanywhere.com"


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _entry_points(files):
    paths = [name for name in files if name.endswith(".dist-info/entry_points.txt")]
    if len(paths) != 1:
        raise ValueError("wheel must contain exactly one entry_points.txt")
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(files[paths[0]].decode("utf-8"))
    return [
        {"name": name, "target": target.strip()}
        for name, target in sorted(parser.items("console_scripts"))
    ]


def _dependencies(files):
    paths = [name for name in files if name.endswith(".dist-info/METADATA")]
    if len(paths) != 1:
        raise ValueError("wheel must contain exactly one METADATA file")
    metadata = BytesParser().parsebytes(files[paths[0]])
    return sorted(metadata.get_all("Requires-Dist", []))


def build_manifest(wheel_path):
    wheel_path = pathlib.Path(wheel_path)
    if wheel_path.suffix != ".whl":
        raise ValueError("manifest input must be a wheel")
    wheel_bytes = wheel_path.read_bytes()
    with zipfile.ZipFile(wheel_path) as archive:
        infos = sorted(
            (info for info in archive.infolist() if not info.is_dir()),
            key=lambda info: info.filename,
        )
        for info in infos:
            path = pathlib.PurePosixPath(info.filename)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"unsafe wheel member: {info.filename}")
        files = {info.filename: archive.read(info) for info in infos}

    inventory = [
        {
            "path": info.filename,
            "size": info.file_size,
            "compressedSize": info.compress_size,
            "sha256": _sha256(files[info.filename]),
        }
        for info in infos
    ]
    native = [item for item in inventory if item["path"].lower().endswith(NATIVE_SUFFIXES)]
    wheel_parts = wheel_path.stem.split("-")
    if len(wheel_parts) < 5:
        raise ValueError("wheel filename does not contain distribution/version/tags")

    return {
        "schema": "agentcomms-package-manifest-v1",
        "scope": "built wheel; source-distribution build behavior is out of scope",
        "distribution": {
            "filename": wheel_path.name,
            "version": wheel_parts[1],
            "size": len(wheel_bytes),
            "sha256": _sha256(wheel_bytes),
            "wheelTags": "-".join(wheel_parts[-3:]),
            "purePython": not native and wheel_parts[-1] == "any",
        },
        "files": inventory,
        "nativeBinaries": native,
        "installBehavior": {
            "installTimeCodeHooks": [],
            "consoleScripts": _entry_points(files),
            "dependencies": _dependencies(files),
            "note": (
                "Installing this wheel unpacks files and creates declared console "
                "scripts; it does not run package-defined install hooks."
            ),
        },
        "declaredNetwork": {
            "defaultPackageCodeOutboundHosts": [DEFAULT_HUB_HOST],
            "operatorConfiguredOutboundHosts": (
                "The --hub option or AGENTCOMMS_HUB may select another HTTP(S) "
                "origin. No other package-code destinations are declared."
            ),
            "offlineSelftestOutboundHosts": [],
            "readOnlyPreflightOutboundHosts": [DEFAULT_HUB_HOST],
            "installerNetwork": (
                "Package-manager index and dependency traffic is controlled by the "
                "installer, not by package code."
            ),
        },
        "reproduction": {
            "command": (
                "python scripts/build_package_manifest.py "
                "dist/<wheel>.whl PACKAGE_MANIFEST_V2.json"
            ),
            "deterministic": True,
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel")
    parser.add_argument("output")
    args = parser.parse_args(argv)
    manifest = build_manifest(args.wheel)
    pathlib.Path(args.output).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    main()
