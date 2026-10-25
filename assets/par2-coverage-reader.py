#!/usr/bin/env python3
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path("/records")
MAGIC = b"PAR2\x00PKT"
FILE_DESC = b"PAR 2.0\x00FileDesc"

def stop(message):
    sys.exit("STOP: " + message)

def checked(relative):
    path = ROOT
    for part in relative.parts:
        path = path / part
        if path.is_symlink():
            stop(f"Symbolic link in records path: {path}")
    return path

def regular(relative):
    path = checked(relative)
    if not path.is_file():
        stop(f"Missing or invalid file: {path}")
    return path

def safe_parts(name):
    return (
        bool(name)
        and not name.startswith("/")
        and "\\" not in name
        and all(part not in ("", ".", "..") for part in name.split("/"))
        and all(ord(char) >= 32 and ord(char) != 127 for char in name)
    )

def read_index(relative, folder):
    path = regular(relative)
    data = path.read_bytes()
    if not data:
        stop(f"Empty PAR2 index: {path}")

    files = set()
    offset = 0
    set_id = None

    while offset < len(data):
        if len(data) - offset < 64:
            stop(f"Truncated PAR2 packet: {path}")

        header = data[offset:offset + 64]
        if header[:8] != MAGIC:
            stop(f"Invalid PAR2 signature: {path}")

        length = struct.unpack_from("<Q", header, 8)[0]
        if length < 64 or length % 4 or offset + length > len(data):
            stop(f"Invalid PAR2 packet length: {path}")

        packet = data[offset:offset + length]
        if hashlib.md5(packet[32:]).digest() != header[16:32]:
            stop(f"PAR2 packet checksum mismatch: {path}")

        if set_id is None:
            set_id = header[32:48]
        elif set_id != header[32:48]:
            stop(f"Conflicting PAR2 set IDs: {path}")

        if header[48:64] == FILE_DESC:
            if length < 120:
                stop("Invalid PAR2 file-description packet.")

            raw = packet[120:].rstrip(b"\x00")
            try:
                name = raw.decode("utf-8")
            except UnicodeDecodeError:
                stop("Unsupported PAR2 filename encoding.")

            if not safe_parts(name) or not name.startswith(folder + "/"):
                stop(f"Unexpected PAR2 filename: {name!r}")

            normalized = "./" + name
            if normalized in files:
                stop("Duplicate PAR2 filename.")
            files.add(normalized)

        offset += length

    if not files:
        stop(f"No described files in PAR2 index: {path}")
    return files

def read_set(relative, folder):
    directory = checked(relative)
    if not directory.is_dir():
        stop(f"Missing recovery-set directory: {directory}")

    index = relative / "recovery.par2"
    regular(index)

    volumes = list(directory.glob("recovery.vol*.par2"))
    if not volumes:
        stop(f"Recovery volumes missing: {directory}")

    for volume in volumes:
        regular(volume.relative_to(ROOT))

    return read_index(index, folder)

if len(sys.argv) != 3:
    stop("Usage: coverage.py DRIVE 'CATEGORY/FOLDER'")

drive, folder = sys.argv[1:]

if not re.fullmatch(r"[A-Za-z0-9._-]+", drive):
    stop("Invalid drive identifier.")

if not safe_parts(folder):
    stop("Invalid archive folder.")

device = Path("devices") / drive
metadata = device / "device.json"
manifest = device / "manifests/baseline.sha256"
parity = Path("parity") / drive / folder
baseline = parity / "baseline"
supplements = parity / "supplements"

# Validate the selected drive against the registry.
try:
    info = json.loads(regular(metadata).read_text(encoding="utf-8"))
except (ValueError, UnicodeError, OSError) as error:
    stop(f"Cannot read device metadata: {error}")

if not isinstance(info, dict) or info.get("device_id") != drive:
    stop("Selected drive does not match registered device metadata.")

print("=== Cold Storage PAR2 Coverage ===")
print(f"Registered drive: {drive}")
print(f"Folder: {folder}")

# A missing SHA-256 baseline is an uninitialized state,
# not evidence that the drive contains zero files.
if not checked(manifest).is_file():
    print("SHA-256 baseline: NOT INITIALIZED")
    print("Registered file count: UNKNOWN")
    print("COVERAGE UNAVAILABLE — Initialize integrity records first.")
    print("READ-ONLY — No files modified.")
    sys.exit(0)

# Load and validate registered filenames.
registered = set()
all_paths = set()
prefix = "./" + folder + "/"

try:
    lines = regular(manifest).read_text(encoding="utf-8").splitlines()
except (UnicodeError, OSError) as error:
    stop(f"Cannot read SHA-256 manifest: {error}")

for line in lines:
    if not re.fullmatch(r"[0-9a-f]{64}  \./.+", line):
        stop("Malformed SHA-256 manifest record.")

    name = line[66:]
    if not safe_parts(name[2:]):
        stop("Unsafe SHA-256 manifest filename.")

    if name in all_paths:
        stop("Duplicate SHA-256 manifest filename.")
    all_paths.add(name)

    if name.startswith(prefix):
        registered.add(name)

if not registered:
    print("Registered files in selected folder: 0")
    print("COVERAGE UNAVAILABLE — Folder has no registered files.")
    print("READ-ONLY — No files modified.")
    sys.exit(0)

baseline_dir = checked(baseline)
supplement_dir = checked(supplements)

# If no PAR2 baseline exists, report pending protection.
if not baseline_dir.exists():
    if supplement_dir.exists():
        stop("Supplements exist without a PAR2 baseline.")

    print(f"SHA-256 registered files: {len(registered)}")
    print("PAR2 baseline: NOT CREATED")
    print(f"Registered files awaiting initial PAR2: {len(registered)}")
    print("STATUS: Initial PAR2 protection not created.")
    print("READ-ONLY — No files modified.")
    sys.exit(0)

protected = read_set(baseline, folder)
baseline_count = len(protected)
supplement_count = 0

if supplement_dir.exists():
    if not supplement_dir.is_dir():
        stop("Invalid supplements directory.")

    for entry in sorted(supplement_dir.iterdir()):
        relative = entry.relative_to(ROOT)
        checked(relative)

        if not entry.is_dir() or entry.name.startswith("."):
            stop(f"Unexpected or incomplete supplement: {entry.name}")

        additional = read_set(relative, folder)
        if protected & additional:
            stop(f"Duplicate PAR2 coverage: {entry.name}")

        protected.update(additional)
        supplement_count += 1

missing = sorted(registered - protected)
unexpected = sorted(protected - registered)

print(f"SHA-256 registered files: {len(registered)}")
print(f"Files in PAR2 baseline: {baseline_count}")
print(f"Completed supplements: {supplement_count}")
print(f"Total PAR2-covered filenames: {len(protected)}")
print(f"Registered files without PAR2: {len(missing)}")
print(f"PAR2 entries absent from SHA-256: {len(unexpected)}")

if missing:
    print("\nRegistered files needing PAR2:")
    for name in missing:
        print("  " + name)

if unexpected:
    print("\nPAR2 entries absent from registration:")
    for name in unexpected:
        print("  " + name)

if not missing and not unexpected:
    print("\nCOVERAGE PASS — All registered filenames are PAR2-covered.")
else:
    print("\nCOVERAGE REVIEW REQUIRED.")

print("READ-ONLY — No files modified.")
print("Note: Archive contents and recovery volumes were not reverified.")
