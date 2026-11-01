#!/usr/bin/env python3
"""Synchronize SHA-256 history without accessing archive mounts."""

import argparse
import json
import os
import re
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from urllib.parse import quote

from app import read_runs, read_issues
from history_sync import sync_history


def synchronize(drive_id):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", drive_id):
        raise ValueError("Unsafe drive identifier")

    records = Path(
        os.environ.get("DEVICES_PATH", "/records/devices")
    )
    database = Path(
        os.environ.get("DB_PATH", "/config/cold_storage.db")
    )

    if not records.is_dir() or records.is_symlink():
        raise ValueError("Device records directory unavailable")

    folder = records / drive_id

    if not folder.is_dir() or folder.is_symlink():
        raise ValueError("Registered drive directory unavailable")

    metadata = folder / "device.json"

    if not metadata.is_file() or metadata.is_symlink():
        raise ValueError("Safe drive metadata unavailable")

    data = json.loads(metadata.read_text(encoding="utf-8"))

    if data.get("device_id") != drive_id:
        raise ValueError("Drive identity does not match records")

    logs = folder / "verification_logs"

    if not logs.is_dir() or logs.is_symlink():
        raise ValueError("Verification log directory unavailable")

    # Parse and validate all history before opening SQLite.
    # These files are stored records, not archive-drive files.
    runs = read_runs(logs / "runs.tsv")
    issues = read_issues(logs / "issues.tsv")

    if (
        not database.is_absolute()
        or not database.is_file()
        or database.is_symlink()
    ):
        raise ValueError(
            "Existing regular SQLite database required; "
            "no database will be created"
        )

    # mode=rw explicitly forbids creating a missing database.
    uri = (
        "file:" + quote(str(database), safe="/") + "?mode=rw"
    )

    with closing(
        sqlite3.connect(uri, uri=True, timeout=30)
    ) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=30000")

        result = sync_history(db, drive_id, runs, issues)

    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Import SHA-256 verification history only"
    )
    parser.add_argument("drive_id")
    args = parser.parse_args(argv)

    try:
        result = synchronize(args.drive_id)
    except Exception as exc:
        print(
            "HISTORY SYNC FAILED: " + str(exc),
            file=sys.stderr
        )
        return 1

    print("HISTORY SYNC: PASS")
    print("Drive:", args.drive_id)
    print("New operation records:", result["runs_added"])
    print("New issue records:", result["issues_added"])
    print(
        "Outstanding integrity failures:",
        result["unresolved_failures"]
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
