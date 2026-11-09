import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, "/work")

import app

DRIVE = "TEST_DISK_SERIAL"
A = "a" * 64
B = "b" * 64
C = "c" * 64


class CatalogRetirementTests(unittest.TestCase):

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)

        root = Path(temp.name)
        self.folder = root / "devices" / DRIVE
        self.db = root / "catalog.db"

        for name in ("manifests", "snapshots", "retirements"):
            (self.folder / name).mkdir(parents=True)

        (self.folder / "device.json").write_text(
            json.dumps({
                "device_id": DRIVE,
                "model": "TEST_DISK",
                "serial": "SERIAL",
            })
        )

        self.before = (
            f"{A}  ./keep.mkv\n"
            f"{B}  ./gone.mkv\n"
        ).encode()

        self.after = f"{A}  ./keep.mkv\n".encode()

        self.manifest = (
            self.folder / "manifests" / "baseline.sha256"
        )

        self.manifest.write_bytes(self.after)

        self.snapshot_name = (
            "baseline_retirement_20261108T100000Z_123.sha256"
        )

        (
            self.folder / "snapshots" / self.snapshot_name
        ).write_bytes(self.before)

        self.receipt = (
            self.folder / "retirements" /
            "retirement_test.tsv"
        )

        self.write_receipt()

        self.inventory = [("keep.mkv", A)]

        self.enterContext(patch.object(
            app, "DB", str(self.db)
        ))

        self.enterContext(patch.object(
            app, "DEVICES", root / "devices"
        ))

        self.enterContext(patch.object(
            app,
            "stage_file_inventories",
            lambda parsed: {DRIVE: list(self.inventory)},
        ))

        self.enterContext(patch.object(
            app,
            "collect_storage_snapshots",
            lambda parsed: ([], []),
        ))

        # Correct the mocked inventory response to match
        # the application's (inventories, messages) contract.
        app.stage_file_inventories = lambda parsed: (
            {DRIVE: list(self.inventory)}, []
        )

        app.init()

        with sqlite3.connect(self.db) as db:
            db.executemany(
                "INSERT INTO files(drive_id,path,sha256) "
                "VALUES(?,?,?)",
                [
                    (DRIVE, "keep.mkv", A),
                    (DRIVE, "gone.mkv", B),
                ],
            )

    def write_receipt(self):
        before_hash = hashlib.sha256(
            self.before
        ).hexdigest()

        after_hash = hashlib.sha256(
            self.after
        ).hexdigest()

        self.receipt.write_text(
            "COLD_SHA_RETIRE_V1\n"
            f"drive\t{DRIVE}\n"
            f"before\t{before_hash}\n"
            f"after\t{after_hash}\n"
            f"snapshot\t{self.snapshot_name}\n"
            f"retired\t{B}\t./gone.mkv\n"
        )

    def catalog(self):
        with sqlite3.connect(self.db) as db:
            return dict(db.execute(
                "SELECT path,sha256 FROM files "
                "WHERE drive_id=?",
                (DRIVE,),
            ).fetchall())

    def test_01_valid_retirement(self):
        count, errors = app.refresh(DRIVE)

        self.assertEqual((count, errors), (1, []))
        self.assertEqual(
            self.catalog(), {"keep.mkv": A}
        )

    def test_02_no_approval_receipt(self):
        self.receipt.unlink()
        before = self.catalog()

        with self.assertRaises(ValueError):
            app.refresh(DRIVE)

        self.assertEqual(self.catalog(), before)

    def test_03_tampered_receipt(self):
        self.receipt.write_text(
            self.receipt.read_text().replace(
                f"retired\t{B}",
                f"retired\t{C}",
            )
        )

        before = self.catalog()

        with self.assertRaises(ValueError):
            app.refresh(DRIVE)

        self.assertEqual(self.catalog(), before)

    def test_04_unchecksummed_approval(self):
        with sqlite3.connect(self.db) as db:
            db.execute(
                "INSERT INTO files VALUES(?,?,?)",
                (DRIVE, "unhashed.mkv", None),
            )

        before = self.catalog()

        with self.assertRaises(
            app.MissingFileApprovalRequired
        ) as context:
            app.refresh(DRIVE)

        self.assertEqual(
            context.exception.paths,
            ("unhashed.mkv",),
        )
        self.assertEqual(self.catalog(), before)

        revision = app.missing_revision(
            DRIVE, ["unhashed.mkv"]
        )

        count, errors = app.refresh(DRIVE, revision)

        self.assertEqual((count, errors), (1, []))
        self.assertEqual(
            self.catalog(), {"keep.mkv": A}
        )

    def test_05_present_file_loses_checksum(self):
        self.inventory = [
            ("keep.mkv", A),
            ("gone.mkv", None),
        ]

        before = self.catalog()

        with self.assertRaises(ValueError):
            app.refresh(DRIVE)

        self.assertEqual(self.catalog(), before)

    def test_06_unapproved_registered_removal(self):
        self.receipt.unlink()

        revision = app.missing_revision(
            DRIVE, ["gone.mkv"]
        )

        before = self.catalog()

        with self.assertRaises(ValueError):
            app.refresh(DRIVE, revision)

        self.assertEqual(self.catalog(), before)

    def test_07_later_registration(self):
        # Later legitimate registrations are allowed.
        self.manifest.write_bytes(
            self.after + f"{C}  ./new.mkv\n".encode()
        )

        self.inventory.append(("new.mkv", C))

        count, errors = app.refresh(DRIVE)

        self.assertEqual((count, errors), (1, []))
        self.assertEqual(
            self.catalog(),
            {
                "keep.mkv": A,
                "new.mkv": C,
            },
        )

    def test_08_new_unregistered_file(self):
        self.inventory.append(("new.mkv", None))

        count, errors = app.refresh(DRIVE)

        self.assertEqual((count, errors), (1, []))
        self.assertEqual(
            self.catalog(),
            {
                "keep.mkv": A,
                "new.mkv": None,
            },
        )



    def test_09_modified_retained_checksum(self):
        from retirement_approval import authorized_retirements

        self.manifest.write_bytes((
            f"{C}  ./keep.mkv\n"
            f"{C}  ./new.mkv\n"
        ).encode())

        with self.assertRaises(ValueError):
            authorized_retirements(
                self.folder,
                DRIVE,
                {"keep.mkv": A, "gone.mkv": B},
                {"keep.mkv", "new.mkv"},
                app.parse_manifest,
            )

    def test_10_retired_checksum_reintroduced(self):
        from retirement_approval import authorized_retirements

        self.manifest.write_bytes(
            self.after + f"{B}  ./gone.mkv\n".encode()
        )

        with self.assertRaises(ValueError):
            authorized_retirements(
                self.folder,
                DRIVE,
                {"keep.mkv": A, "gone.mkv": B},
                {"keep.mkv"},
                app.parse_manifest,
            )

    def test_11_older_retirement_receipt(self):
        older_before = (
            f"{A}  ./keep.mkv\n"
            f"{C}  ./old.mkv\n"
            f"{B}  ./gone.mkv\n"
        ).encode()

        older_snapshot = (
            "baseline_retirement_20261107T100000Z_122.sha256"
        )

        (
            self.folder / "snapshots" / older_snapshot
        ).write_bytes(older_before)

        older_receipt = (
            self.folder / "retirements" /
            "retirement_older.tsv"
        )

        older_receipt.write_text(
            "COLD_SHA_RETIRE_V1\n"
            f"drive\t{DRIVE}\n"
            f"before\t{hashlib.sha256(older_before).hexdigest()}\n"
            f"after\t{hashlib.sha256(self.before).hexdigest()}\n"
            f"snapshot\t{older_snapshot}\n"
            f"retired\t{C}\t./old.mkv\n"
        )

        count, errors = app.refresh(DRIVE)

        self.assertEqual((count, errors), (1, []))
        self.assertEqual(
            self.catalog(), {"keep.mkv": A}
        )

    def test_12_forged_after_digest(self):
        original_digest = hashlib.sha256(
            self.after
        ).hexdigest()

        self.receipt.write_text(
            self.receipt.read_text().replace(
                f"after\t{original_digest}",
                f"after\t{'0' * 64}",
            )
        )

        before = self.catalog()

        with self.assertRaises(ValueError):
            app.refresh(DRIVE)

        self.assertEqual(self.catalog(), before)



    def run_targeted_cli(self):
        import io
        import os
        from contextlib import redirect_stdout, redirect_stderr
        from catalog_refresh_cli import main

        stdout = io.StringIO()
        stderr = io.StringIO()

        environment = {
            "DB_PATH": str(self.db),
            "DEVICES_PATH": str(self.folder.parent),
        }

        with patch.dict(os.environ, environment):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = main([DRIVE])

        return result, stdout.getvalue(), stderr.getvalue()

    def test_13_cli_recovers_stale_sqlite(self):
        # The manifest and receipt reflect a completed
        # retirement, but SQLite still has both records.
        self.assertEqual(
            self.catalog(),
            {"keep.mkv": A, "gone.mkv": B},
        )

        original_receipt = self.receipt.read_bytes()
        original_manifest = self.manifest.read_bytes()

        result, stdout, stderr = self.run_targeted_cli()

        self.assertEqual(result, 0, stderr)
        self.assertIn("CATALOG REFRESH: PASS", stdout)
        self.assertEqual(
            self.catalog(), {"keep.mkv": A}
        )

        # A second refresh must be idempotent.
        result, stdout, stderr = self.run_targeted_cli()

        self.assertEqual(result, 0, stderr)
        self.assertIn("CATALOG REFRESH: PASS", stdout)
        self.assertEqual(
            self.catalog(), {"keep.mkv": A}
        )

        self.assertEqual(
            self.receipt.read_bytes(), original_receipt
        )
        self.assertEqual(
            self.manifest.read_bytes(), original_manifest
        )

        print("PASS: SQLite recovery and repeat refresh")

    def test_14_cli_rejects_uncommitted_retirement(self):
        # Approval receipt exists, but active manifest
        # still contains the supposedly retired file.
        self.manifest.write_bytes(self.before)

        before_catalog = self.catalog()

        result, stdout, stderr = self.run_targeted_cli()

        self.assertEqual(result, 1)
        self.assertIn("CATALOG REFRESH FAILED", stderr)
        self.assertEqual(self.catalog(), before_catalog)
        self.assertEqual(
            self.manifest.read_bytes(), self.before
        )

        print("PASS: Incomplete retirement rejected")

    def test_15_cli_rejects_missing_receipt(self):
        self.receipt.unlink()
        before_catalog = self.catalog()

        result, stdout, stderr = self.run_targeted_cli()

        self.assertEqual(result, 1)
        self.assertIn("CATALOG REFRESH FAILED", stderr)
        self.assertEqual(self.catalog(), before_catalog)

        print("PASS: Missing receipt rejected")

    def test_16_cli_rejects_tampered_receipt(self):
        original = self.receipt.read_text()

        expected_line = (
            "after\t"
            + hashlib.sha256(self.after).hexdigest()
        )

        self.assertIn(expected_line, original)

        self.receipt.write_text(
            original.replace(
                expected_line,
                "after\t" + "0" * 64,
            )
        )

        before_catalog = self.catalog()

        result, stdout, stderr = self.run_targeted_cli()

        self.assertEqual(result, 1)
        self.assertIn("CATALOG REFRESH FAILED", stderr)
        self.assertEqual(self.catalog(), before_catalog)

        print("PASS: Tampered receipt rejected")

    def test_17_cli_recovers_retirement_and_registration(self):
        # The host completed retirement and registered
        # an additional file before SQLite was refreshed.
        self.manifest.write_bytes(
            self.after + f"{C}  ./new.mkv\n".encode()
        )

        self.inventory.append(("new.mkv", C))

        self.assertEqual(
            self.catalog(),
            {"keep.mkv": A, "gone.mkv": B},
        )

        result, stdout, stderr = self.run_targeted_cli()

        self.assertEqual(result, 0, stderr)
        self.assertIn("CATALOG REFRESH: PASS", stdout)

        self.assertEqual(
            self.catalog(),
            {"keep.mkv": A, "new.mkv": C},
        )

        print("PASS: Retirement and registration recovered")


if __name__ == "__main__":
    unittest.main(verbosity=2)
