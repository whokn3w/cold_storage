
"""Checksum-record and unresolved-failure indicators.

Green: checksum recorded, no known outstanding failure.
Gray: checksum absent, no known outstanding failure.
Red: known outstanding file-specific integrity failure.

Green does NOT mean the file has passed verification.
"""


def _empty_summary():
    return {
        "total": 0,
        "recorded": 0,
        "failed": 0,
    }


def _add(summary, recorded, failed):
    summary["total"] += 1
    summary["recorded"] += int(recorded)
    summary["failed"] += int(failed)


def summary_status(summary):
    if summary["failed"]:
        return "red"

    if (
        summary["total"] > 0
        and summary["recorded"] == summary["total"]
    ):
        return "green"

    return "gray"


def build_indicator_index(records, unresolved_failures=()):
    """Summarize file and folder states using catalog metadata.

    records: iterable with drive_id, path, sha256 fields.
    unresolved_failures: (drive_id, path) pairs established
        from persistent file-specific verification history.

    Folder totals include all descendant files.
    Identical paths on separate drives count separately.
    """

    failures = set(unresolved_failures)

    files = {}
    drive_folders = {}
    combined_folders = {}
    drives = {}

    for row in records:
        drive = row["drive_id"]
        path = row["path"]
        checksum = row["sha256"]

        key = (drive, path)

        if key in files:
            raise ValueError(
                "Duplicate catalog identity: " + repr(key)
            )

        recorded = checksum is not None and checksum != ""
        failed = key in failures

        files[key] = (
            "red" if failed else
            "green" if recorded else
            "gray"
        )

        drive_summary = drives.setdefault(
            drive, _empty_summary()
        )
        _add(drive_summary, recorded, failed)

        parts = path.split("/")

        # Each physical file contributes once to every ancestor.
        for depth in range(1, len(parts)):
            folder = "/".join(parts[:depth])

            drive_summary = drive_folders.setdefault(
                (drive, folder),
                _empty_summary()
            )
            _add(drive_summary, recorded, failed)

            combined_summary = combined_folders.setdefault(
                folder,
                _empty_summary()
            )
            _add(combined_summary, recorded, failed)

    return {
        "files": files,
        "drive_folders": drive_folders,
        "combined_folders": combined_folders,
        "drives": drives,
    }


def checkmark_html(status):
    """Accessible circular checkmark with theme-aware colors."""

    labels = {
        "green": "SHA-256 checksum recorded",
        "gray": "SHA-256 checksum not recorded",
        "red": "Outstanding file integrity failure",
    }

    theme_classes = {
        "green": "good",
        "gray": "muted",
        "red": "bad",
    }

    if status not in labels:
        raise ValueError("Unknown indicator status")

    label = labels[status]
    theme_class = theme_classes[status]

    return (
        '<span class="checksum-check checksum-'
        + status
        + ' '
        + theme_class
        + '" role="img" title="'
        + label
        + '" aria-label="'
        + label
        + '">'
        '<svg viewBox="0 0 24 24" '
        'width="18" height="18" '
        'fill="none" stroke="currentColor" '
        'stroke-width="2" '
        'stroke-linecap="round" '
        'stroke-linejoin="round" '
        'aria-hidden="true">'
        '<circle cx="12" cy="12" r="9"/>'
        + (
            '<path d="M9 9l6 6m0-6-6 6"/>'
            if status == "red"
            else '<path d="m8 12 2.7 2.7L16 9.5"/>'
        )
        + '</svg></span>'
    )
