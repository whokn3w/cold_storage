import hashlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, "/work")
sys.path.insert(0, "/app")

from app import parse_manifest
from retirement_approval import authorized_retirements


class RetirementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.drive = "TEST_DISK_SERIAL"
        self.folder = Path(self.temp.name) / self.drive

        for directory in (
            "manifests", "snapshots", "retirements"
        ):
            (self.folder / directory).mkdir(parents=True)

        self.a = "a" * 64
        self.b = "b" * 64

        self.before = (
            f"{self.a}  ./keep.mkv\n"
            f"{self.b}  ./gone.mkv\n"
        ).encode()

        self.after = (
            f"{self.a}  ./keep.mkv\n"
        ).encode()

        self.snapshot_name = (
            "baseline_retirement_20261108T100000Z_123.sha256"
        )

        self.snapshot = (
            self.folder / "snapshots" / self.snapshot_name
        )
        self.manifest = (
            self.folder / "manifests" / "baseline.sha256"
        )
        self.receipt = (
            self.folder / "retirements" /
            "retirement_test.tsv"
        )

        self.snapshot.write_bytes(self.before)
        self.manifest.write_bytes(self.after)

        before_hash = hashlib.sha256(self.before).hexdigest()
        after_hash = hashlib.sha256(self.after).hexdigest()

        self.receipt.write_text(
            "COLD_SHA_RETIRE_V1\n"
            f"drive\t{self.drive}\n"
            f"before\t{before_hash}\n"
            f"after\t{after_hash}\n"
            f"snapshot\t{self.snapshot_name}\n"
            f"retired\t{self.b}\t./gone.mkv\n"
        )

        self.saved = {
            "keep.mkv": self.a,
            "gone.mkv": self.b,
        }
        self.physical = {"keep.mkv"}

    def validate(self):
        return authorized_retirements(
            self.folder,
            self.drive,
            self.saved,
            self.physical,
            parse_manifest,
        )

    def test_valid_retirement(self):
        self.assertEqual(
            self.validate(), {"gone.mkv"}
        )

    def test_no_missing_records(self):
        self.physical.add("gone.mkv")
        self.assertEqual(self.validate(), set())

    def test_wrong_retired_checksum(self):
        contents = self.receipt.read_text()
        self.receipt.write_text(
            contents.replace(
                f"retired\t{self.b}",
                f"retired\t{'c' * 64}"
            )
        )
        with self.assertRaises(ValueError):
            self.validate()

    def test_tampered_snapshot(self):
        self.snapshot.write_bytes(
            self.before + b"altered\n"
        )
        with self.assertRaises(ValueError):
            self.validate()

    def test_changed_active_manifest(self):
        self.manifest.write_bytes(self.before)
        with self.assertRaises(ValueError):
            self.validate()

    def test_unapproved_additional_removal(self):
        self.saved["another-gone.mkv"] = "c" * 64
        with self.assertRaises(ValueError):
            self.validate()

    def test_duplicate_receipt(self):
        shutil.copyfile(
            self.receipt,
            self.folder / "retirements" /
            "retirement_duplicate.tsv",
        )
        with self.assertRaises(ValueError):
            self.validate()

    def test_symbolic_link_snapshot(self):
        self.snapshot.unlink()
        self.snapshot.symlink_to(self.manifest)
        with self.assertRaises(ValueError):
            self.validate()

    def test_incomplete_receipt(self):
        with self.receipt.open("ab") as output:
            output.write(b"incomplete")
        with self.assertRaises(ValueError):
            self.validate()


if __name__ == "__main__":
    unittest.main(verbosity=2)
