import datetime
import sqlite3
import unittest
from zoneinfo import ZoneInfo

from dashboard_attention import (
    checksum_coverage,
    verification_schedule,
)


TZ = ZoneInfo("America/Detroit")
DRIVE = "TEST_DISK_SERIAL"
HASH = "a" * 64


class DashboardAttentionTests(unittest.TestCase):

    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)

        self.db.executescript("""
            CREATE TABLE files (
                drive_id TEXT,
                path TEXT,
                sha256 TEXT
            );
            CREATE TABLE runs (
                drive_id TEXT,
                seq INTEGER,
                stamp TEXT,
                action TEXT,
                result TEXT,
                tracked INTEGER,
                delta INTEGER,
                issues INTEGER
            );
        """)

        self.drive = {
            "id": DRIVE,
            "last_pass": None,
            "interval_days": 180,
        }

    def file(self, path, digest=HASH):
        self.db.execute(
            "INSERT INTO files VALUES (?,?,?)",
            (DRIVE, path, digest),
        )

    def record_run(self, seq, stamp, action, result, delta=0):
        self.db.execute(
            "INSERT INTO runs VALUES (?,?,?,?,?,?,?,?)",
            (DRIVE, seq, stamp, action, result, 0, delta, 0),
        )

    def schedule(self, today):
        return verification_schedule(
            self.db, self.drive, TZ, today=today
        )

    def test_partial_checksum_coverage(self):
        self.file("registered.mkv")
        self.file("unregistered.mkv", None)
        self.file("empty-checksum.mkv", "")

        self.assertEqual(
            checksum_coverage(self.db, DRIVE),
            {
                "cataloged": 3,
                "registered": 1,
                "unregistered": 2,
            },
        )

    def test_no_checksum_means_no_schedule(self):
        self.file("catalog-only.mkv", None)
        self.record_run(
            1, "2026-11-09T12:00:00Z",
            "register", "PASS", 1,
        )

        self.assertIsNone(
            self.schedule(datetime.date(2026, 11, 9))
        )

    def test_first_registration_starts_interval(self):
        self.file("movie.mkv")
        self.record_run(
            1, "2026-11-09T12:00:00Z",
            "register", "PASS", 1,
        )

        result = self.schedule(datetime.date(2026, 11, 9))

        self.assertEqual(
            result["due_date"],
            datetime.date(2026, 11, 9)
            + datetime.timedelta(days=180),
        )
        self.assertEqual(result["days_remaining"], 180)
        self.assertEqual(
            result["basis"], "first_checksum_registration"
        )

    def test_additional_registration_does_not_reset_due_date(self):
        self.file("original.mkv")
        self.file("new.mkv")

        self.record_run(
            1, "2026-01-01T12:00:00Z",
            "register", "PASS", 1,
        )
        self.record_run(
            2, "2026-05-01T12:00:00Z",
            "register", "PASS", 1,
        )

        result = self.schedule(datetime.date(2026, 5, 2))

        self.assertEqual(
            result["due_date"],
            datetime.date(2026, 1, 1)
            + datetime.timedelta(days=180),
        )

    def test_successful_verification_starts_new_interval(self):
        self.file("original.mkv")
        self.file("new.mkv")

        self.record_run(
            1, "2026-01-01T12:00:00Z",
            "register", "PASS", 1,
        )
        self.record_run(
            2, "2026-06-01T12:00:00Z",
            "verify", "PASS",
        )
        self.record_run(
            3, "2026-08-01T12:00:00Z",
            "register", "PASS", 1,
        )

        self.drive["last_pass"] = "2026-06-01T12:00:00Z"

        result = self.schedule(datetime.date(2026, 8, 2))

        self.assertEqual(
            result["due_date"],
            datetime.date(2026, 6, 1)
            + datetime.timedelta(days=180),
        )
        self.assertEqual(
            result["basis"], "successful_verification"
        )

    def test_failed_verification_does_not_reset_interval(self):
        self.file("movie.mkv")
        self.record_run(
            1, "2026-01-01T12:00:00Z",
            "register", "PASS", 1,
        )
        self.record_run(
            2, "2026-02-01T12:00:00Z",
            "verify", "FAIL",
        )

        result = self.schedule(datetime.date(2026, 3, 1))

        self.assertEqual(
            result["due_date"],
            datetime.date(2026, 1, 1)
            + datetime.timedelta(days=180),
        )

    def test_missing_registration_history_does_not_invent_date(self):
        self.file("movie.mkv")

        self.assertIsNone(
            self.schedule(datetime.date(2026, 11, 9))
        )

    def test_utc_timestamp_uses_local_calendar_date(self):
        self.file("movie.mkv")
        self.record_run(
            1, "2026-11-09T02:00:00Z",
            "register", "PASS", 1,
        )

        result = self.schedule(datetime.date(2026, 11, 9))

        self.assertEqual(
            result["due_date"],
            datetime.date(2026, 11, 8)
            + datetime.timedelta(days=180),
        )


if __name__ == "__main__":
    unittest.main()
