"""Dashboard rendering tests using fictional in-memory drive records."""

import datetime
import sqlite3
import unittest
from unittest.mock import patch

import app


DRIVE = "TEST_DASHBOARD_DISK"
HASH = "a" * 64


class DashboardRenderingTests(unittest.TestCase):

    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.addCleanup(self.db.close)

        self.db.executescript("""
            CREATE TABLE drives (
                id TEXT PRIMARY KEY,
                model TEXT,
                serial TEXT,
                capacity INTEGER,
                registered TEXT,
                interval_days INTEGER,
                file_count INTEGER,
                last_pass TEXT,
                last_verify TEXT,
                last_result TEXT,
                pending INTEGER,
                latest_registration TEXT
            );

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

            CREATE TABLE storage_snapshots (
                drive_id TEXT,
                used_bytes INTEGER,
                available_bytes INTEGER,
                captured_at TEXT
            );

            CREATE TABLE drive_tags (
                drive_id TEXT,
                tag TEXT
            );
        """)

        self.today = datetime.datetime.now(
            app.LOCAL_TZ
        ).date()

    def stamp(self, days_ago=0):
        day = self.today - datetime.timedelta(
            days=days_ago
        )
        return day.isoformat() + "T12:00:00Z"

    def add_run(
        self, seq, stamp, action, result,
        tracked=0, delta=0, issues=0
    ):
        self.db.execute(
            "INSERT INTO runs VALUES (?,?,?,?,?,?,?,?)",
            (
                DRIVE, seq, stamp, action,
                result, tracked, delta, issues
            ),
        )

    def render(self, hashes, last_pass=None, pending=0, par2_status="NOT INITIALIZED"):
        self.db.execute(
            "INSERT INTO drives VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                DRIVE,
                "TEST DISK",
                "TEST SERIAL",
                1_000_000,
                None,
                180,
                len(hashes),
                last_pass,
                None,
                None,
                pending,
                None,
            ),
        )

        for index, digest in enumerate(hashes):
            self.db.execute(
                "INSERT INTO files VALUES (?,?,?)",
                (
                    DRIVE,
                    f"file_{index}.mkv",
                    digest,
                ),
            )

        row = self.db.execute(
            "SELECT * FROM drives WHERE id=?",
            (DRIVE,),
        ).fetchone()

        with patch.object(
            app,
            "par2_record_status",
            return_value=(par2_status, "muted", ""),
        ):
            return app.storage_overview(self.db, [row])

    def test_new_baseline_has_countdown_not_immediate_warning(self):
        self.add_run(
            1, self.stamp(), "register", "PASS",
            tracked=2, delta=2,
        )

        html = self.render(
            [HASH, HASH],
            pending=1,
        )

        self.assertNotIn(
            "SHA-256 checksum baseline recorded",
            html,
        )
        self.assertNotIn(
            "Next SHA-256 check in 180 day(s)",
            html,
        )
        self.assertNotIn(
            "New SHA-256 registrations await verification",
            html,
        )
        self.assertNotIn(
            "SHA-256 checksum verification needed",
            html,
        )

    def test_partial_checksum_coverage_is_visible(self):
        self.add_run(
            1, self.stamp(), "register", "PASS",
            tracked=1, delta=1,
        )

        html = self.render(
            [HASH, None, None],
            pending=1,
        )

        self.assertIn(
            "2 cataloged file(s) need SHA-256 checksums",
            html,
        )
        self.assertNotIn(
            "Next SHA-256 check in 180 day(s)",
            html,
        )

    def test_new_registration_does_not_extend_old_deadline(self):
        older = self.stamp(days_ago=60)

        self.add_run(
            1, self.stamp(days_ago=120),
            "register", "PASS",
            tracked=1, delta=1,
        )
        self.add_run(
            2, older, "verify", "PASS",
            tracked=1,
        )
        self.add_run(
            3, self.stamp(), "register", "PASS",
            tracked=2, delta=1,
        )

        html = self.render(
            [HASH, HASH],
            last_pass=older,
            pending=1,
        )

        self.assertNotIn(
            "Additional SHA-256 checksums recorded",
            html,
        )
        self.assertNotIn(
            "Next SHA-256 check in 120 day(s)",
            html,
        )
        self.assertNotIn(
            "Next SHA-256 check in 180 day(s)",
            html,
        )

    def test_failure_and_missing_checksums_both_visible(self):
        self.add_run(
            1, self.stamp(days_ago=10),
            "register", "PASS",
            tracked=1, delta=1,
        )
        self.add_run(
            2, self.stamp(days_ago=2),
            "verify", "FAIL",
            tracked=1, issues=1,
        )

        html = self.render(
            [HASH, None],
            pending=1,
        )

        self.assertIn(
            "SHA-256 checksum verification reported issues",
            html,
        )
        self.assertIn(
            "1 cataloged file(s) need SHA-256 checksums",
            html,
        )
        self.assertNotIn(
            "Next SHA-256 check in",
            html,
        )

    def test_overdue_countdown(self):
        self.add_run(
            1, self.stamp(days_ago=190),
            "register", "PASS",
            tracked=1, delta=1,
        )

        html = self.render(
            [HASH],
            pending=1,
        )

        self.assertIn(
            "SHA-256 verification overdue by 10 day(s)",
            html,
        )

    def test_catalog_only_files_have_no_fake_due_date(self):
        html = self.render(
            [None, None],
            pending=0,
        )

        self.assertIn(
            "2 cataloged file(s) need SHA-256 checksums",
            html,
        )
        self.assertNotIn(
            "Next SHA-256 check in",
            html,
        )
        self.assertNotIn(
            "SHA-256 verification overdue",
            html,
        )


    def test_sha_attention_has_distinct_accent(self):
        self.add_run(
            1, self.stamp(), "register", "PASS",
            tracked=1, delta=1,
        )

        html = self.render([HASH, None], pending=1)

        self.assertIn(
            'class="attention-item attention-sha"',
            html,
        )
        self.assertIn(
            "1 cataloged file(s) need SHA-256 checksums",
            html,
        )

    def test_par2_failure_has_distinct_accent(self):
        self.add_run(
            1, self.stamp(), "register", "PASS",
            tracked=1, delta=1,
        )

        html = self.render(
            [HASH],
            pending=1,
            par2_status="FAILED",
        )

        self.assertIn(
            'class="attention-item attention-par2"',
            html,
        )
        self.assertIn(
            "PAR2 recovery verification FAILED",
            html,
        )

    def test_par2_coverage_does_not_create_attention(self):
        self.add_run(
            1, self.stamp(), "register", "PASS",
            tracked=1, delta=1,
        )

        html = self.render(
            [HASH],
            pending=1,
            par2_status="COVERAGE RECORDED",
        )

        self.assertIn("Attention:</strong> No flags", html)
        self.assertNotIn(
            "PAR2 coverage recorded; verification not recorded",
            html,
        )


    def test_accent_css_is_inside_style_tags(self):
        import re

        css = app.CSS

        marker = (
            "/* Dashboard protection-system accents: "
            "purely decorative. */"
        )

        self.assertIn(marker, css)

        blocks = re.findall(
            r"<style\b[^>]*>(.*?)</style>",
            css,
            flags=re.IGNORECASE | re.DOTALL,
        )

        self.assertTrue(
            any(
                marker in block
                and "--cold-sha-accent" in block
                and "--cold-par2-accent" in block
                for block in blocks
            )
        )

        outside_styles = re.sub(
            r"<style\b[^>]*>.*?</style>",
            "",
            css,
            flags=re.IGNORECASE | re.DOTALL,
        )

        self.assertNotIn(marker, outside_styles)



if __name__ == "__main__":
    unittest.main()
