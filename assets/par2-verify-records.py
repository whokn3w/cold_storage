#!/usr/bin/env python3
"""Development-only PAR2 set inventory and verification receipts."""

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/records/parity")
REGISTRY = Path("/config/par2-selections.json")
HISTORY = Path("/config/par2-verification-history.jsonl")


def stop(message):
    raise SystemExit("STOP: " + message)


def safe(value):
    return (
        isinstance(value, str)
        and bool(value)
        and not value.startswith("/")
        and "\\" not in value
        and all(p not in ("", ".", "..") for p in value.split("/"))
        and all(32 <= ord(c) != 127 for c in value)
    )


def no_links(path):
    current = Path("/")
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            stop("Symbolic link in recovery path.")


def inventory(drive):
    if not re.fullmatch(r"[A-Za-z0-9._-]+", drive):
        stop("Invalid drive identifier.")

    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        stop("Unsupported selection registry.")

    folders = data["drives"].get(drive, [])
    if not isinstance(folders, list):
        stop("Invalid drive selections.")

    results = []

    for folder in folders:
        if not safe(folder):
            stop("Unsafe selected folder.")

        parent = ROOT / drive / folder
        no_links(parent)

        baseline = parent / "baseline"
        supplements = parent / "supplements"

        candidates = [("baseline", baseline)]

        if supplements.exists():
            no_links(supplements)
            if not supplements.is_dir():
                stop("Invalid supplements directory.")

            for child in sorted(supplements.iterdir()):
                if (
                    not child.is_dir()
                    or child.is_symlink()
                    or child.name.startswith(".")
                ):
                    stop("Incomplete or unexpected supplement.")
                candidates.append(
                    ("supplements/" + child.name, child)
                )

        for name, directory in candidates:
            no_links(directory)

            if not directory.is_dir():
                stop("Missing recovery-set directory.")

            index = directory / "recovery.par2"
            no_links(index)

            if not index.is_file():
                stop("Missing recovery index.")

            volumes = sorted(directory.glob("recovery.vol*.par2"))

            if not volumes:
                stop("Missing recovery volumes.")

            for volume in volumes:
                no_links(volume)
                if not volume.is_file():
                    stop("Invalid recovery volume.")

            results.append((folder, name, index, volumes))

    return results


def fingerprint(index, volumes):
    """Bind a receipt to index content and recovery-file metadata."""
    entries = []

    for path in [index, *volumes]:
        no_links(path)
        stat = path.stat()
        entries.append({
            "name": path.name,
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
        })

    entries[0]["sha256"] = hashlib.sha256(
        index.read_bytes()
    ).hexdigest()

    encoded = json.dumps(
        entries, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")

    return hashlib.sha256(encoded).hexdigest()


def main():
    if len(sys.argv) < 3:
        stop("Usage: plan DRIVE | record DRIVE FOLDER SET RUN_ID EVENT")

    action, drive = sys.argv[1:3]
    sets = inventory(drive)

    if action == "plan":
        if len(sys.argv) != 3:
            stop("Unexpected plan arguments.")

        print("Drive:", drive)

        if not sets:
            print("PAR2: NOT SELECTED")
            return

        for folder, name, index, volumes in sets:
            print(
                f"{folder} | {name} | "
                f"{len(volumes)} recovery volumes"
            )

        print("Recovery sets:", len(sets))
        print("No verification executed.")
        return

    if action != "record" or len(sys.argv) != 7:
        stop("Invalid action or arguments.")

    folder, name, run_id, event = sys.argv[3:7]

    if not re.fullmatch(r"[A-Za-z0-9._-]+", run_id):
        stop("Invalid verification run identifier.")

    if event not in ("START", "PASS", "FAIL"):
        stop("Invalid verification event.")

    match = [
        (index, volumes)
        for selected, set_name, index, volumes in sets
        if selected == folder and set_name == name
    ]

    if len(match) != 1:
        stop("Recovery set is not in the current selection plan.")

    index, volumes = match[0]

    receipt = {
        "schema_version": 1,
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(timespec="seconds"),
        "drive": drive,
        "folder": folder,
        "set": name,
        "run_id": run_id,
        "event": event,
        "fingerprint": fingerprint(index, volumes),
    }

    line = (
        json.dumps(receipt, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    fd = os.open(
        HISTORY,
        os.O_WRONLY | os.O_APPEND | os.O_CREAT,
        0o644,
    )

    try:
        if os.write(fd, line) != len(line):
            stop("Could not write complete verification receipt.")
        os.fsync(fd)
    finally:
        os.close(fd)

    print(f"Recorded {event}: {folder} / {name}")


if __name__ == "__main__":
    main()
