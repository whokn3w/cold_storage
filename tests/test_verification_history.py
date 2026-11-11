import html
import sqlite3
import unittest

from verification_history import render_verification_history


class VerificationHistoryTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row

        self.db.executescript(
            "CREATE TABLE runs ("
            "drive_id TEXT,seq INTEGER,stamp TEXT,"
            "action TEXT,result TEXT,"
            "tracked INTEGER,delta INTEGER,issues INTEGER);"
            "CREATE TABLE issues ("
            "drive_id TEXT,seq INTEGER,raw TEXT);"
        )

    def tearDown(self):
        self.db.close()

    def render(self):
        return render_verification_history(
            self.db,
            lambda value: html.escape(value, quote=True),
            lambda stamp: stamp,
        )

    def add_run(
        self, seq, action, result,
        tracked=10, delta=0, issues=0,
        drive="Example_Drive",
        stamp="2026-11-10T01:00:00Z",
    ):
        self.db.execute(
            "INSERT INTO runs VALUES (?,?,?,?,?,?,?,?)",
            (
                drive, seq, stamp, action,
                result, tracked, delta, issues,
            ),
        )

    def test_empty_history(self):
        page = self.render()
        self.assertIn("No operations recorded yet", page)
        self.assertIn("No historical issue records", page)

    def test_registration_is_not_verification(self):
        self.add_run(1, "register", "PASS", 50, 12, 0)

        page = self.render()

        self.assertIn("Registration completed", page)
        self.assertIn("New checksums", page)
        self.assertIn("SHA-256 registration", page)
        self.assertNotIn("Verification passed", page)

    def test_verification_counts_are_distinct(self):
        self.add_run(1, "verify", "PASS", 50, 3, 0)

        page = self.render()

        self.assertIn("Verification passed", page)
        self.assertIn("Unregistered files", page)
        self.assertIn("Tracked Files", page)

    def test_incomplete_has_unknown_issue_count(self):
        self.add_run(
            1, "verify", "INCOMPLETE",
            tracked=227, issues=-1,
        )

        page = self.render()

        self.assertIn("Verification incomplete", page)
        self.assertIn("Unknown (incomplete)", page)
        self.assertNotIn("<td>-1</td>", page)

    def test_failure_is_not_success(self):
        self.add_run(1, "verify", "FAIL", issues=2)

        page = self.render()

        self.assertIn("Verification failed", page)
        self.assertNotIn("Verification passed", page)

    def test_issue_paths_are_escaped_and_historical(self):
        self.db.execute(
            "INSERT INTO issues VALUES (?,?,?)",
            (
                "Example_Drive", 1,
                "2026-11-10T01:00:00Z"
                "\tUNREGISTERED\t./<script>alert(1)</script>",
            ),
        )

        page = self.render()

        self.assertIn("historical observations", page)
        self.assertIn("UNREGISTERED", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<script>", page)

    def test_same_second_runs_are_not_merged(self):
        self.add_run(1, "verify", "PASS")
        self.add_run(2, "verify", "INCOMPLETE", issues=-1)

        page = self.render()

        self.assertIn("Verification passed", page)
        self.assertIn("Verification incomplete", page)
        self.assertIn("latest 2 of 2", page)

    def test_recent_history_is_bounded(self):
        for seq in range(1, 204):
            self.add_run(
                seq, "register", "PASS",
                drive=f"Drive_{seq}",
                stamp=(
                    f"2026-11-10T01:"
                    f"{seq // 60:02d}:{seq % 60:02d}Z"
                ),
            )

        page = self.render()

        self.assertIn("latest 200 of 203", page)
        self.assertIn("Drive_203", page)
        self.assertNotIn("<code>Drive_1</code>", page)


if __name__ == "__main__":
    unittest.main()
