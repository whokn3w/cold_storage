
"""Resolve outstanding SHA-256 failures from saved verification logs.

Read-only history processing. No hashing or archive access.
"""

CRITICAL_KINDS = frozenset({
    "HASH_MISMATCH", "MISSING", "READ_ERROR",
})
KNOWN_KINDS = CRITICAL_KINDS | {"UNREGISTERED"}


def normalize_issue_path(path):
    if not isinstance(path, str) or not path:
        raise ValueError("Empty integrity issue path")

    if path.startswith("./"):
        path = path[2:]

    if (
        not path
        or path.startswith("/")
        or any(
            part in ("", ".", "..")
            for part in path.split("/")
        )
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in path)
    ):
        raise ValueError("Unsafe integrity issue path")

    return path


def unresolved_failures(drive_id, runs, issues):
    """Return unresolved (drive_id, relative_path) pairs.

    Only a complete recorded verification PASS clears old failures.
    Registration, FAIL, and INCOMPLETE cannot clear them.
    """

    if not isinstance(drive_id, str) or not drive_id:
        raise ValueError("Invalid drive ID")

    run_list = list(runs)
    verification_stamps = set()

    for record in run_list:
        if len(record) != 6:
            raise ValueError("Invalid verification run record")

        stamp, action, result, tracked, delta, count = record

        if action == "verify":
            if stamp in verification_stamps:
                raise ValueError(
                    "Ambiguous same-second verification history"
                )
            verification_stamps.add(stamp)

    issue_by_stamp = {}

    for raw in issues:
        fields = raw.split("\t", 2)

        if len(fields) != 3:
            raise ValueError("Malformed integrity issue record")

        stamp, kind, raw_path = fields

        if not stamp or kind not in KNOWN_KINDS:
            raise ValueError("Unknown integrity issue record")

        path = normalize_issue_path(raw_path)

        if (
            kind in CRITICAL_KINDS
            and stamp not in verification_stamps
        ):
            raise ValueError(
                "Integrity failure has no matching verification run"
            )

        issue_by_stamp.setdefault(stamp, []).append(
            (kind, path)
        )

    pending = set()

    for stamp, action, result, tracked, delta, count in run_list:
        if action != "verify":
            continue

        current = issue_by_stamp.get(stamp, [])

        if result == "PASS":
            if (
                tracked < 0 or delta != 0
                or count != 0 or current
            ):
                raise ValueError(
                    "Inconsistent successful verification record"
                )
            pending.clear()

        elif result in ("FAIL", "INCOMPLETE"):
            for kind, path in current:
                if kind in CRITICAL_KINDS:
                    pending.add((drive_id, path))
        else:
            raise ValueError(
                "Unknown verification result: " + str(result)
            )

    return pending
