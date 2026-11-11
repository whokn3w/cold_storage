import datetime
import html
import json
import tempfile
import unittest
from pathlib import Path

from verification_progress import read_progress
from verification_progress_view import render_verification_progress


UTC = datetime.timezone.utc


class ProgressViewTests(unittest.TestCase):

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)

        self.device = Path(temporary.name) / "synthetic-device"
        self.logs = self.device / "verification_logs"
        self.logs.mkdir(parents=True)

        self.now = datetime.datetime(
            2026, 11, 10, 4, 0, tzinfo=UTC
        )

    def snapshot(self, **changes):
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

        (self.logs / "verify_progress.json").write_text(
            json.dumps(data),
            encoding="utf-8",
        )

    def render(self, now=None, when=None):
        return render_verification_progress(
            self.device,
            lambda text: html.escape(str(text), quote=True),
            when or (lambda value: value),
            now=self.now if now is None else now,
        )

    def test_missing_snapshot_is_hidden(self):
        self.assertEqual(self.render(), "")

    def test_running_shows_actual_counts(self):
        self.snapshot()
        page = self.render()

        self.assertIn("recent progress update", page)
        self.assertIn("240 / 400", page)
        self.assertIn("Hashes calculated", page)
        self.assertIn(">239</strong>", page)
        self.assertIn("Issues detected", page)
        self.assertIn("File-processing progress: 60%", page)
        self.assertIn('value="240"', page)
        self.assertIn('max="400"', page)
        self.assertNotIn("Verification passed", page)

    def test_finished_processing_is_not_pass(self):
        self.snapshot(
            phase="finished",
            processed=400,
            hashed=398,
            issues=2,
        )

        page = self.render()

        self.assertIn("File processing completed", page)
        self.assertIn("100%", page)
        self.assertIn("verification history", page)
        self.assertNotIn("Verification passed", page)

    def test_interrupted_is_not_success(self):
        self.snapshot(
            phase="interrupted",
            processed=100,
            hashed=99,
        )

        page = self.render()

        self.assertIn("Verification interrupted", page)
        self.assertIn("100 / 400", page)
        self.assertIn("25%", page)
        self.assertNotIn("Verification passed", page)

    def test_stale_running_record_not_called_active(self):
        self.snapshot()

        later = datetime.datetime(
            2026, 11, 10, 4, 10, tzinfo=UTC
        )

        page = self.render(now=later)

        self.assertIn("No recent progress update", page)
        self.assertIn("may have stalled or stopped", page)
        self.assertNotIn(
            "Processing — recent progress update",
            page,
        )

    def test_invalid_phase_type_is_ignored(self):
        self.snapshot(phase=["running"])

        self.assertIsNone(
            read_progress(self.device, now=self.now)
        )
        self.assertEqual(self.render(), "")

    def test_zero_tracked_files_has_no_progress_bar(self):
        self.snapshot(
            phase="finished",
            total=0,
            processed=0,
            hashed=0,
            issues=0,
        )

        page = self.render()

        self.assertIn("No tracked files", page)
        self.assertNotIn("<progress", page)

    def test_localized_timestamp_is_escaped(self):
        self.snapshot()

        page = self.render(
            when=lambda value: "<script>unsafe</script>"
        )

        self.assertIn(
            "&lt;script&gt;unsafe&lt;/script&gt;",
            page,
        )
        self.assertNotIn("<script>", page)


if __name__ == "__main__":
    unittest.main()
