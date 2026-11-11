"""HTTP progress endpoint tests using disposable metadata only."""

import datetime
import http.client
import json
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

import app


UTC = datetime.timezone.utc


class ProgressEndpointTests(unittest.TestCase):

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)

        root = Path(temporary.name)
        db_path = root / "catalog" / "test.db"
        devices = root / "devices"
        devices.mkdir()

        for name, value in (
            ("DB", str(db_path)),
            ("DEVICES", devices),
            ("BACKUPS", root / "backups"),
        ):
            replacement = patch.object(app, name, value)
            replacement.start()
            self.addCleanup(replacement.stop)

        app.init()

        self.drive = "SYNTHETIC_PROGRESS_TEST"

        with app.connect() as db:
            db.execute(
                "INSERT INTO drives ("
                "id,model,serial,capacity,registered,"
                "interval_days,file_count"
                ") VALUES (?,?,?,?,?,?,?)",
                (
                    self.drive,
                    "Synthetic Drive",
                    "SYNTHETIC",
                    1000000,
                    "2026-11-11T07:00:00Z",
                    180,
                    4,
                ),
            )
            db.commit()

        self.logs = (
            devices / self.drive / "verification_logs"
        )
        self.logs.mkdir(parents=True)

        class QuietHandler(app.Handler):
            def log_message(self, *args):
                pass

        from http.server import ThreadingHTTPServer

        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            QuietHandler,
        )
        self.server.daemon_threads = True

        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()
        self.addCleanup(self.stop_server)

        self.started = (
            datetime.datetime.now(UTC)
            - datetime.timedelta(seconds=60)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())

    def snapshot(self, phase="running", **changes):
        now = datetime.datetime.now(UTC)
        data = {
            "schema": 1,
            "run_id": self.started + "-12345",
            "started_at": self.started,
            "updated_at": now.strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "phase": phase,
            "total": 4,
            "processed": 2,
            "hashed": 2,
            "issues": 0,
            "unregistered": 0,
        }
        data.update(changes)
        (self.logs / "verify_progress.json").write_text(
            json.dumps(data), encoding="utf-8"
        )

    def request(self, ident=None):
        if ident is None:
            ident = self.drive

        path = "/verify-progress?" + urllib.parse.urlencode(
            {"id": ident}
        )

        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.server.server_address[1],
            timeout=5,
        )

        try:
            connection.request("GET", path)
            result = connection.getresponse()
            body = result.read().decode("utf-8")
            return result.status, body, result.headers
        finally:
            connection.close()

    def test_running_progress_over_http(self):
        self.snapshot()

        status, body, headers = self.request()

        self.assertEqual(status, 200)
        self.assertIn("2 / 4", body)
        self.assertIn("File-processing progress: 50%", body)
        self.assertIn('data-progress-poll="true"', body)
        self.assertIn("no-store", headers["Cache-Control"])
        self.assertNotIn("<!doctype html>", body)

    def test_finished_progress_stops_polling(self):
        self.snapshot(
            phase="finished",
            processed=4,
            hashed=3,
            issues=1,
        )

        status, body, _ = self.request()

        self.assertEqual(status, 200)
        self.assertIn("File processing completed", body)
        self.assertIn('data-progress-poll="false"', body)
        self.assertNotIn("Verification passed", body)

    def test_missing_and_invalid_snapshots(self):
        status, body, _ = self.request()
        self.assertEqual((status, body), (204, ""))

        self.snapshot(phase=["running"])
        status, body, _ = self.request()
        self.assertEqual((status, body), (204, ""))

    def test_rejects_invalid_and_unknown_drives(self):
        for ident, expected in (
            ("../other", 400),
            (".", 400),
            ("..", 400),
            ("UNKNOWN_SYNTHETIC_DRIVE", 404),
        ):
            status, body, _ = self.request(ident)
            self.assertEqual(status, expected)
            self.assertEqual(body, "")

    def test_rejects_symlinked_device_directory(self):
        alias = "SYNTHETIC_ALIAS"
        target = self.logs.parent
        link = self.logs.parent.parent / alias
        link.symlink_to(target, target_is_directory=True)

        with app.connect() as db:
            db.execute(
                "INSERT INTO drives(id,model,file_count) "
                "VALUES (?,?,?)",
                (alias, "Synthetic Alias", 4),
            )
            db.commit()

        status, body, _ = self.request(alias)
        self.assertEqual(status, 404)
        self.assertEqual(body, "")


    def read_path(self, path):
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.server.server_address[1],
            timeout=5,
        )
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            body = response.read().decode("utf-8")
            return response.status, body, response.headers
        finally:
            connection.close()

    def test_live_drive_page_renders_polling_container(self):
        self.snapshot()

        status, page, _ = self.read_path(
            "/drive?id=" + urllib.parse.quote(self.drive)
        )

        self.assertEqual(status, 200)
        self.assertIn('id="verify-progress-live"', page)
        self.assertIn(
            'data-drive-id="SYNTHETIC_PROGRESS_TEST"',
            page,
        )
        self.assertIn(
            '/assets/verify-progress-live.js',
            page,
        )
        self.assertIn('data-progress-poll="true"', page)

        self.assertLess(
            page.index("SHA-256 Checksum Verification"),
            page.index('id="verify-progress-live"'),
        )
        self.assertLess(
            page.index('id="verify-progress-live"'),
            page.index("Recent Operations"),
        )

    def test_live_drive_page_handles_absent_and_finished(self):
        path = "/drive?id=" + urllib.parse.quote(self.drive)

        status, page, _ = self.read_path(path)

        self.assertEqual(status, 200)
        self.assertIn('id="verify-progress-live"', page)
        self.assertIn(
            '/assets/verify-progress-live.js',
            page,
        )
        self.assertNotIn(
            'aria-label="SHA-256 verification progress"',
            page,
        )

        self.snapshot(
            phase="finished",
            processed=4,
            hashed=3,
            issues=1,
        )

        status, page, _ = self.read_path(path)

        self.assertEqual(status, 200)
        self.assertIn('id="verify-progress-live"', page)
        self.assertIn('data-progress-poll="false"', page)
        self.assertIn("File processing completed", page)
        self.assertNotIn("Verification passed", page)

    def test_live_script_is_served_as_javascript(self):
        status, script, headers = self.read_path(
            "/assets/verify-progress-live.js"
        )

        self.assertEqual(status, 200)
        self.assertIn(
            "application/javascript",
            headers["Content-Type"],
        )
        self.assertIn("no-cache", headers["Cache-Control"])
        self.assertIn("intervalMs = 10000", script)
        self.assertIn("holder.replaceChildren(panel)", script)
        self.assertIn("response.status === 204", script)
        self.assertIn("visibilitychange", script)
        self.assertNotIn("location.reload", script)

    def test_live_script_not_added_to_history_page(self):
        status, page, _ = self.read_path("/history")

        self.assertEqual(status, 200)
        self.assertIn(
            "Verification and registration history",
            page,
        )
        self.assertNotIn(
            '/assets/verify-progress-live.js',
            page,
        )


if __name__ == "__main__":
    unittest.main()
