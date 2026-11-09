import hashlib
import tempfile
import unittest
from pathlib import Path

from app import parse_manifest
from retirement_approval import authorized_retirements

DRIVE = "TEST_DISK_SERIAL"
KEEP = "a" * 64
GONE = "b" * 64
NEW = "c" * 64

BEFORE = (
    f"{KEEP}  ./keep.mkv\n"
    f"{GONE}  ./gone.mkv\n"
).encode()

AFTER = f"{KEEP}  ./keep.mkv\n".encode()

SNAP_NAME = (
    "baseline_retirement_20261109T000000Z_123.sha256"
)

SAVED = {
    "keep.mkv": KEEP,
    "gone.mkv": GONE,
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


class RetirementRecoveryTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.folder = Path(self.temp.name) / DRIVE

        for name in (
            "manifests",
            "snapshots",
            "retirements",
        ):
            (self.folder / name).mkdir(parents=True)

        self.manifest = (
            self.folder / "manifests" / "baseline.sha256"
        )

        self.manifest.write_bytes(BEFORE)

        self.snapshot = (
            self.folder / "snapshots" / SNAP_NAME
        )

        self.snapshot.write_bytes(BEFORE)

        self.receipt = (
            self.folder / "retirements"
            / "retirement_20261109T000000Z_123.tsv"
        )

    def publish_receipt(self, after_digest=None):
        if after_digest is None:
            after_digest = sha(AFTER)

        content = (
            "COLD_SHA_RETIRE_V1\n"
            f"drive\t{DRIVE}\n"
            f"before\t{sha(BEFORE)}\n"
            f"after\t{after_digest}\n"
            f"snapshot\t{SNAP_NAME}\n"
            f"retired\t{GONE}\t./gone.mkv\n"
        )

        self.receipt.write_text(content)

    def authorize(self, saved=None, physical=None):
        return authorized_retirements(
            self.folder,
            DRIVE,
            SAVED if saved is None else saved,
            {"keep.mkv"} if physical is None else physical,
            parse_manifest,
        )

    def test_01_receipt_without_manifest_commit_rejected(self):
        self.publish_receipt()

        with self.assertRaises(ValueError):
            self.authorize()

        self.assertEqual(
            self.manifest.read_bytes(), BEFORE
        )

    def test_02_completed_retirement_can_be_reimported(self):
        self.publish_receipt()
        self.manifest.write_bytes(AFTER)

        # Simulate a catalog still holding the old SHA record
        # after a failed synchronization.
        self.assertEqual(
            self.authorize(), {"gone.mkv"}
        )

        # Rechecking the same unchanged evidence remains valid.
        self.assertEqual(
            self.authorize(), {"gone.mkv"}
        )

    def test_03_updated_catalog_needs_no_second_approval(self):
        self.publish_receipt()
        self.manifest.write_bytes(AFTER)

        updated_saved = {"keep.mkv": KEEP}

        self.assertEqual(
            self.authorize(saved=updated_saved),
            set(),
        )

    def test_04_missing_receipt_fails_closed(self):
        self.manifest.write_bytes(AFTER)

        with self.assertRaises(ValueError):
            self.authorize()

    def test_05_duplicate_approval_receipts_fail_closed(self):
        self.publish_receipt()
        self.manifest.write_bytes(AFTER)

        duplicate = (
            self.folder / "retirements"
            / "retirement_20261109T000001Z_124.tsv"
        )

        duplicate.write_bytes(self.receipt.read_bytes())

        with self.assertRaises(ValueError):
            self.authorize()

    def test_06_later_registration_preserves_approval(self):
        self.publish_receipt()

        self.manifest.write_bytes(
            AFTER + f"{NEW}  ./new.mkv\n".encode()
        )

        self.assertEqual(
            self.authorize(
                physical={"keep.mkv", "new.mkv"}
            ),
            {"gone.mkv"},
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
