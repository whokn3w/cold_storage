#!/usr/bin/env python3
"""Refresh exactly one registered archive drive.

The application performs its own hardware-identity checks.
This command never starts the web server.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path


def refresh_one(drive_id):
    if not re.fullmatch(
        r"[A-Za-z0-9._-]{1,256}", drive_id
    ):
        raise ValueError("Unsafe target drive identifier")

    database = Path(
        os.environ.get("DB_PATH", "/config/cold_storage.db")
    )
    devices = Path(
        os.environ.get("DEVICES_PATH", "/records/devices")
    )

    if (
        not database.is_absolute()
        or database.is_symlink()
        or not database.is_file()
    ):
        raise ValueError(
            "Existing regular catalog database required"
        )

    if (
        not devices.is_absolute()
        or devices.is_symlink()
        or not devices.is_dir()
    ):
        raise ValueError(
            "Safe device records directory required"
        )

    folder = devices / drive_id

    if folder.is_symlink() or not folder.is_dir():
        raise ValueError(
            "Selected drive registration is unavailable"
        )

    metadata = folder / "device.json"

    if metadata.is_symlink() or not metadata.is_file():
        raise ValueError(
            "Selected drive metadata is unavailable"
        )

    data = json.loads(
        metadata.read_text(encoding="utf-8")
    )

    if data.get("device_id") != drive_id:
        raise ValueError(
            "Selected drive registration identity mismatch"
        )

    # Import only after the path and registration checks.
    # app.py does not start its server when imported.
    from app import refresh

    count, errors = refresh(drive_id)

    if errors:
        raise RuntimeError(
            "Targeted catalog refresh stopped: "
            + "; ".join(str(error) for error in errors)
        )

    if count != 1:
        raise RuntimeError(
            "Targeted refresh did not confirm exactly one drive"
        )

    return count


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Refresh one registered archive catalog"
    )
    parser.add_argument("drive_id")
    args = parser.parse_args(argv)

    try:
        count = refresh_one(args.drive_id)
    except Exception as exc:
        print(
            "CATALOG REFRESH FAILED: " + str(exc),
            file=sys.stderr
        )
        return 1

    print("CATALOG REFRESH: PASS")
    print("Drive:", args.drive_id)
    print("Registered drives processed:", count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
