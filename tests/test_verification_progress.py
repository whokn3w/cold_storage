import datetime
import json
import tempfile
import unittest
from pathlib import Path

from verification_progress import (
    parse_progress,
    read_progress,
)


UTC = datetime.timezone.utc


class VerificationProgressTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.datetime(
            2026, 11, 10, 4, 0, tzinfo=UTC
        )

    def sample(self, **changes):
        data = {
            "schema": 1,
            "run_id": "2026-11-10T03:59:00Z-12345",
            "started_at": "2026-11-10T03:59:00Z",
            "updated_at": "2026-11-10T03:59:30Z",
            "phase": "running",
            "total": 400,
            "processed": 240,
            "hashed": 239,
            "issues": 1,
            "unregistered": 0,
        }
        data.update(changes)
        return data

    def parse(self, **changes):
        return parse_progress(
            json.dumps(self.sample(**changes)).encode(),
            now=self.now,
        )

    def test_real_processed_count(self):
        progress = self.parse()

        self.assertEqual(progress["percent"], 60)
        self.assertEqual(progress["processed"], 240)
        self.assertEqual(progress["hashed"], 239)
        self.assertEqual(progress["issues"], 1)
        self.assertTrue(progress["recent"])

    def test_processing_complete_is_not_verification(self):
        progress = self.parse(
            phase="finished",
            processed=400,
            hashed=399,
        )

        self.assertEqual(progress["percent"], 100)
        self.assertEqual(progress["phase"], "finished")
        self.assertNotIn("verified", progress)
        self.assertNotIn("outcome", progress)

    def test_interrupted_progress_is_not_success(self):
        progress = self.parse(
            phase="interrupted",
            processed=100,
            hashed=100,
            issues=0,
        )

        self.assertEqual(progress["percent"], 25)
        self.assertEqual(progress["phase"], "interrupted")
        self.assertNotIn("outcome", progress)

    def test_stale_progress_is_not_recent(self):
        progress = self.parse(
            started_at="2026-11-10T00:00:00Z",
            run_id="2026-11-10T00:00:00Z-12345",
            updated_at="2026-11-10T00:05:00Z",
        )

        self.assertFalse(progress["recent"])

    def test_future_progress_is_rejected(self):
        with self.assertRaises(ValueError):
            self.parse(
                updated_at="2026-11-11T00:00:00Z"
            )

    def test_impossible_counts_rejected(self):
        for changes in (
            {"processed": 401},
            {"hashed": 241},
            {"issues": -1},
            {"unregistered": 2},
            {"total": True},
            {"phase": "finished", "processed": 399},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    self.parse(**changes)

    def test_invalid_schema_and_extra_fields_rejected(self):
        with self.assertRaises(ValueError):
            self.parse(schema=2)

        with self.assertRaises(ValueError):
            self.parse(outcome="PASS")

    def test_zero_tracked_files_has_no_percentage(self):
        progress = self.parse(
            phase="finished",
            total=0,
            processed=0,
            hashed=0,
            issues=0,
        )

        self.assertIsNone(progress["percent"])

    def test_invalid_json_rejected(self):
        with self.assertRaises(ValueError):
            parse_progress(b"{invalid", now=self.now)

    def test_missing_progress_returns_none(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertIsNone(
                read_progress(folder, now=self.now)
            )

    def test_valid_progress_file_can_be_read(self):
        with tempfile.TemporaryDirectory() as folder:
            logs = Path(folder) / "verification_logs"
            logs.mkdir()

            path = logs / "verify_progress.json"
            path.write_text(
                json.dumps(self.sample()),
                encoding="utf-8",
            )

            value = read_progress(folder, now=self.now)

            self.assertIsNotNone(value)
            self.assertEqual(value["processed"], 240)

    def test_symlinked_progress_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            logs = Path(folder) / "verification_logs"
            logs.mkdir()

            target = Path(folder) / "outside.json"
            target.write_text(
                json.dumps(self.sample()),
                encoding="utf-8",
            )

            (logs / "verify_progress.json").symlink_to(
                target
            )

            self.assertIsNone(
                read_progress(folder, now=self.now)
            )


if __name__ == "__main__":
    unittest.main()
