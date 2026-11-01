
"""Transactional SHA-256 history synchronization.

No archive mounts, file scans, checksums, or network operations.
Only preexisting registered drives may receive history updates.
"""

import re

from failure_records import (
    unresolved_failures,
    normalize_issue_path,
    KNOWN_KINDS,
)


def sync_history(db, drive_id, runs, issues):
    """Append validated history while preserving the file catalog.

    Caller supplies already-parsed run and issue records.
    This function owns one SQLite transaction.

    A successful full verification may resolve old failures.
    Registration and failed verification cannot clear them.
    """

    if db.in_transaction:
        raise ValueError("History sync requires a fresh transaction")

    if (
        not isinstance(drive_id, str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]+", drive_id)
    ):
        raise ValueError("Invalid registered drive ID")

    incoming_runs = [tuple(record) for record in runs]
    incoming_issues = list(issues)

    for record in incoming_runs:
        if (
            len(record) != 6
            or record[1] not in ("register", "verify")
            or record[2] not in (
                "PASS", "FAIL", "INCOMPLETE", "NO_CHANGES"
            )
            or (
                record[2] == "NO_CHANGES"
                and record[1] != "register"
            )
            or any(
                not isinstance(value, int)
                for value in record[3:]
            )
        ):
            raise ValueError("Invalid incoming run")

    verify_stamps = {
        record[0]
        for record in incoming_runs
        if record[1] == "verify"
    }

    for raw in incoming_issues:
        if not isinstance(raw, str):
            raise ValueError("Invalid incoming issue")

        parts = raw.split("\t")

        if len(parts) != 3:
            raise ValueError("Malformed incoming issue")

        stamp, kind, path = parts

        if kind not in KNOWN_KINDS:
            raise ValueError("Unknown integrity issue type")

        normalize_issue_path(path)

        if stamp not in verify_stamps:
            raise ValueError(
                "Integrity issue has no matching verification run"
            )

    # Resolve and validate before opening the write transaction.
    outstanding = unresolved_failures(
        drive_id, incoming_runs, incoming_issues
    )

    try:
        db.execute("BEGIN IMMEDIATE")

        exists = db.execute(
            "SELECT id FROM drives WHERE id=?",
            (drive_id,)
        ).fetchone()

        if exists is None:
            raise ValueError(
                "History sync requires an existing registered drive"
            )

        old_run_rows = db.execute(
            "SELECT seq,stamp,action,result,tracked,delta,issues "
            "FROM runs WHERE drive_id=? ORDER BY seq",
            (drive_id,)
        ).fetchall()

        old_issue_rows = db.execute(
            "SELECT seq,raw FROM issues "
            "WHERE drive_id=? ORDER BY seq",
            (drive_id,)
        ).fetchall()

        old_runs = [tuple(row)[1:] for row in old_run_rows]
        old_issues = [tuple(row)[1] for row in old_issue_rows]

        if any(
            tuple(row)[0] != position
            for position, row in enumerate(old_run_rows)
        ):
            raise ValueError("Stored run sequence is inconsistent")

        if any(
            tuple(row)[0] != position
            for position, row in enumerate(old_issue_rows)
        ):
            raise ValueError("Stored issue sequence is inconsistent")

        for label, previous, current in (
            ("runs", old_runs, incoming_runs),
            ("issues", old_issues, incoming_issues),
        ):
            if (
                len(current) < len(previous)
                or current[:len(previous)] != previous
            ):
                raise ValueError(
                    f"{drive_id}: {label} history missing "
                    "or altered; database unchanged"
                )

        for index in range(len(old_runs), len(incoming_runs)):
            db.execute(
                "INSERT INTO runs VALUES (?,?,?,?,?,?,?,?)",
                (drive_id, index, *incoming_runs[index])
            )

        for index in range(
            len(old_issues), len(incoming_issues)
        ):
            db.execute(
                "INSERT INTO issues VALUES (?,?,?)",
                (drive_id, index, incoming_issues[index])
            )

        verifications = [
            record
            for record in incoming_runs
            if record[1] == "verify"
        ]

        passes = [
            record
            for record in verifications
            if record[2] == "PASS"
        ]

        registrations = [
            record
            for record in incoming_runs
            if record[1] == "register"
            and record[2] == "PASS"
        ]

        last_verify = (
            verifications[-1] if verifications else None
        )
        last_pass = passes[-1][0] if passes else None
        last_registration = (
            registrations[-1][0] if registrations else None
        )

        pending = int(bool(
            last_registration
            and (
                not last_pass
                or last_registration > last_pass
            )
        ))

        # Do not modify drives.file_count or any file checksum.
        db.execute(
            "UPDATE drives SET "
            "last_pass=?,last_verify=?,last_result=?,"
            "pending=?,latest_registration=? "
            "WHERE id=?",
            (
                last_pass,
                last_verify[0] if last_verify else None,
                last_verify[2] if last_verify else None,
                pending,
                last_registration,
                drive_id,
            )
        )

        db.commit()

    except BaseException:
        db.rollback()
        raise

    return {
        "runs_added": len(incoming_runs) - len(old_runs),
        "issues_added": len(incoming_issues) - len(old_issues),
        "unresolved_failures": len(outstanding),
    }
