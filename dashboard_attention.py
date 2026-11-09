"""Read-only SHA-256 coverage and integrity scheduling helpers.

Checksum registration establishes a baseline, not an immediate
obligation to verify. Later registrations must not postpone checks
due for files whose baseline was already established.
"""

import datetime


def checksum_coverage(db, drive_id):
    """Count cataloged files with and without saved SHA-256 values."""
    total = db.execute(
        "SELECT COUNT(*) FROM files WHERE drive_id=?",
        (drive_id,),
    ).fetchone()[0]

    registered = db.execute(
        "SELECT COUNT(*) FROM files "
        "WHERE drive_id=? AND sha256 IS NOT NULL AND sha256 != ''",
        (drive_id,),
    ).fetchone()[0]

    if registered > total:
        raise ValueError("Checksum coverage exceeds catalog inventory")

    return {
        "cataloged": total,
        "registered": registered,
        "unregistered": total - registered,
    }


def verification_schedule(db, drive, local_tz, today=None):
    """Calculate a due date without scanning or hashing archive files.

    The latest successful full verification starts a new interval.
    Without a successful verification, use the FIRST successful
    nonempty SHA-256 registration, not the most recent registration.

    Missing trustworthy history yields no invented deadline.
    """
    coverage = checksum_coverage(db, drive["id"])

    if coverage["registered"] == 0:
        return None

    stamp = drive["last_pass"]
    basis = "successful_verification"

    if not stamp:
        row = db.execute(
            "SELECT stamp FROM runs "
            "WHERE drive_id=? AND action='register' "
            "AND result='PASS' AND delta>0 "
            "ORDER BY seq ASC LIMIT 1",
            (drive["id"],),
        ).fetchone()

        if row is None:
            return None

        stamp = row[0]
        basis = "first_checksum_registration"

    try:
        parsed = datetime.datetime.fromisoformat(
            stamp.replace("Z", "+00:00")
        )
    except (ValueError, TypeError, AttributeError):
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)

    interval = int(drive["interval_days"] or 180)

    if interval < 1:
        return None

    due_date = (
        parsed.astimezone(local_tz).date()
        + datetime.timedelta(days=interval)
    )

    if today is None:
        today = datetime.datetime.now(local_tz).date()

    return {
        "due_date": due_date,
        "days_remaining": (due_date - today).days,
        "basis": basis,
    }
