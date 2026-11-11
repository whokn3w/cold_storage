"""Read-only, non-authoritative SHA-256 progress metadata.

Progress means files inspected, not files verified successfully.
Only permanent integrity history determines verification outcomes.
"""

import datetime
import json
import os
import re
import stat
from pathlib import Path


MAX_BYTES = 4096

FIELDS = {
    "schema", "run_id", "started_at", "updated_at",
    "phase", "total", "processed", "hashed",
    "issues", "unregistered",
}

STATES = {"running", "finished", "interrupted"}

COUNTERS = (
    "total", "processed", "hashed", "issues", "unregistered",
)

STAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
)

RUN_ID = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z-[1-9]\d{0,9}"
)


def _timestamp(value):
    if not isinstance(value, str) or not STAMP.fullmatch(value):
        raise ValueError("Invalid progress timestamp")

    return datetime.datetime.strptime(
        value, "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=datetime.timezone.utc)


def parse_progress(raw, now=None):
    """Validate one progress snapshot without trusting its outcome."""

    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError("Invalid progress data size")

    data = json.loads(raw.decode("utf-8"))

    if type(data) is not dict or set(data) != FIELDS:
        raise ValueError("Unexpected progress fields")

    if type(data["schema"]) is not int or data["schema"] != 1:
        raise ValueError("Unsupported progress schema")

    if (
        not isinstance(data["run_id"], str)
        or not RUN_ID.fullmatch(data["run_id"])
        or data["run_id"].rsplit("-", 1)[0] != data["started_at"]
    ):
        raise ValueError("Invalid progress run identifier")

    if type(data["phase"]) is not str or data["phase"] not in STATES:
        raise ValueError("Unknown progress phase")

    for name in COUNTERS:
        value = data[name]

        if type(value) is not int or value < 0 or value > 1000000000:
            raise ValueError("Invalid progress counter: " + name)

    total = data["total"]
    processed = data["processed"]
    hashed = data["hashed"]

    if processed > total or hashed > processed:
        raise ValueError("Inconsistent progress counters")

    if data["unregistered"] > data["issues"]:
        raise ValueError("Unregistered files exceed issue count")

    if data["phase"] == "finished" and processed != total:
        raise ValueError("Finished processing has incomplete counters")

    started = _timestamp(data["started_at"])
    updated = _timestamp(data["updated_at"])

    if updated < started:
        raise ValueError("Progress update precedes start")

    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)

    if not isinstance(now, datetime.datetime) or now.tzinfo is None:
        raise ValueError("An aware UTC reference time is required")

    age = (now.astimezone(datetime.timezone.utc) - updated).total_seconds()

    if age < -300:
        raise ValueError("Progress timestamp is implausibly in the future")

    return {
        "run_id": data["run_id"],
        "phase": data["phase"],
        "total": total,
        "processed": processed,
        "hashed": hashed,
        "issues": data["issues"],
        "unregistered": data["unregistered"],
        "updated_at": data["updated_at"],
        "recent": -5 <= age <= 120,
        "percent": (
            (processed * 100) // total if total else None
        ),
    }


def read_progress(device_folder, now=None):
    """Read the bounded metadata file, never an archive file."""

    path = (
        Path(device_folder)
        / "verification_logs"
        / "verify_progress.json"
    )

    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )

    try:
        fd = os.open(path, flags)

        with os.fdopen(fd, "rb") as stream:
            details = os.fstat(stream.fileno())

            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_size > MAX_BYTES
            ):
                return None

            raw = stream.read(MAX_BYTES + 1)

        return parse_progress(raw, now=now)

    except (OSError, ValueError):
        return None
