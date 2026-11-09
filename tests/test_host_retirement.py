import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, "/work")
sys.path.insert(0, "/app")

from app import parse_manifest
from retirement_approval import authorized_retirements

SOURCE = Path(
    "/work/host-tools/approved-sha-removals/integrity.sh"
).read_text()

START = 'if [[ "$MODE" == retire ]]; then'
END = '\nif [[ "$MODE" == register ]]; then'

assert SOURCE.count(START) == 1
assert SOURCE.count(END) == 1

RETIRE_BLOCK = (
    START + SOURCE.split(START, 1)[1].split(END, 1)[0]
)

DRIVE = "TEST_DISK_SERIAL"
A = "a" * 64
B = "b" * 64


class HostRetirementTests(unittest.TestCase):

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)

        root = Path(temp.name)
        self.mount = root / "archive"
        self.folder = root / "records" / DRIVE

        self.mount.mkdir()

        for name in ("manifests", "snapshots"):
            (self.folder / name).mkdir(parents=True)

        (self.mount / "keep.mkv").write_bytes(b"test-content")

        self.manifest = (
            self.folder / "manifests" / "baseline.sha256"
        )

        self.before = (
            f"{A}  ./keep.mkv\n"
            f"{B}  ./gone.mkv\n"
        ).encode()

        self.after = f"{A}  ./keep.mkv\n".encode()

        self.manifest.write_bytes(self.before)

        self.inventory = root / "initial-inventory"
        self.inventory.write_bytes(b"./keep.mkv\0")

        self.known = {
            "./keep.mkv": A,
            "./gone.mkv": B,
        }

    def receipts(self):
        return list(
            self.folder.glob("retirements/retirement_*.tsv")
        )

    def snapshots(self):
        return list(
            self.folder.glob(
                "snapshots/baseline_retirement_*.sha256"
            )
        )

    def run_retire(
        self, answer="", hook="", expected_drive=DRIVE
    ):
        lines = [
            "set -Eeuo pipefail",
            "MODE=retire",
            "ID=" + shlex.quote(DRIVE),
            "COLD_EXPECTED_DEVICE_ID="
            + shlex.quote(expected_drive),
            "MOUNT=" + shlex.quote(str(self.mount)),
            "DIR=" + shlex.quote(str(self.folder)),
            "MANIFEST=" + shlex.quote(str(self.manifest)),
            "ALL_LIST=" + shlex.quote(str(self.inventory)),
            "STAGED=''",
            "RESCAN=''",
            "RECEIPT_TMP=''",
            "COMPLETED=0",
            'die() { echo "ERROR: $*" >&2; exit 1; }',
            "declare -A KNOWN=()",
        ]

        for path, checksum in self.known.items():
            lines.append(
                f"KNOWN[{shlex.quote(path)}]="
                f"{shlex.quote(checksum)}"
            )

        lines.extend([
            """
init_retirement_mount() { :; }
verify_retirement_mount() { :; }

cleanup() {
  [[ -z "$STAGED" ]] || rm -f -- "$STAGED"
  [[ -z "$RESCAN" ]] || rm -f -- "$RESCAN"
  [[ -z "$RECEIPT_TMP" ]] || rm -f -- "$RECEIPT_TMP"
}
trap cleanup EXIT
""",
            hook,
            RETIRE_BLOCK,
        ])

        return subprocess.run(
            ["bash", "-c", "\n".join(lines)],
            input=answer + "\n",
            text=True,
            capture_output=True,
        )

    def test_01_successful_retirement(self):
        result = self.run_retire(f"RETIRE 1 {DRIVE}")

        self.assertEqual(
            result.returncode, 0, result.stderr
        )
        self.assertEqual(
            self.manifest.read_bytes(), self.after
        )

        self.assertEqual(len(self.receipts()), 1)
        self.assertEqual(len(self.snapshots()), 1)

        self.assertEqual(
            self.snapshots()[0].read_bytes(),
            self.before,
        )

        approved = authorized_retirements(
            self.folder,
            DRIVE,
            {"keep.mkv": A, "gone.mkv": B},
            {"keep.mkv"},
            parse_manifest,
        )

        self.assertEqual(approved, {"gone.mkv"})
        print("PASS: Retirement, snapshot and receipt")

    def test_02_cancellation(self):
        result = self.run_retire("CANCEL")

        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            self.manifest.read_bytes(), self.before
        )
        self.assertFalse(self.receipts())
        self.assertFalse(self.snapshots())

        print("PASS: Cancellation preserves everything")

    def test_03_no_missing_files(self):
        self.manifest.write_bytes(self.after)
        self.known = {"./keep.mkv": A}

        result = self.run_retire()

        self.assertEqual(
            result.returncode, 0, result.stderr
        )
        self.assertEqual(
            self.manifest.read_bytes(), self.after
        )
        self.assertFalse(self.receipts())

        print("PASS: No retirement when nothing is missing")

    def test_04_changed_inventory(self):
        self.inventory.write_bytes(
            b"./keep.mkv\0./old-extra.mkv\0"
        )

        result = self.run_retire(f"RETIRE 1 {DRIVE}")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Physical inventory changed",
            result.stderr,
        )
        self.assertEqual(
            self.manifest.read_bytes(), self.before
        )
        self.assertFalse(self.receipts())

        print("PASS: Changed inventory rejected")

    def test_05_missing_path_is_symlink(self):
        (self.mount / "gone.mkv").symlink_to(
            self.mount / "not-present"
        )

        result = self.run_retire(f"RETIRE 1 {DRIVE}")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symbolic link", result.stderr)
        self.assertEqual(
            self.manifest.read_bytes(), self.before
        )

        print("PASS: Symbolic link rejected")

    def test_06_failure_before_receipt(self):
        result = self.run_retire(
            f"RETIRE 1 {DRIVE}",
            hook="sync() { return 1; }",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            self.manifest.read_bytes(), self.before
        )
        self.assertFalse(self.receipts())

        print("PASS: Early flush failure preserves baseline")

    def test_07_failure_after_receipt(self):
        hook = """
SYNC_CALLS=0
sync() {
  SYNC_CALLS=$((SYNC_CALLS + 1))
  [[ "$SYNC_CALLS" -ne 2 ]]
}
"""
        result = self.run_retire(
            f"RETIRE 1 {DRIVE}", hook=hook
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            self.manifest.read_bytes(), self.before
        )
        self.assertEqual(len(self.receipts()), 1)

        # An incomplete publication must not authorize
        # removal from the catalog.
        with self.assertRaises(ValueError):
            authorized_retirements(
                self.folder,
                DRIVE,
                {"keep.mkv": A, "gone.mkv": B},
                {"keep.mkv"},
                parse_manifest,
            )

        print("PASS: Incomplete publication not authorized")



    def test_08_mount_change_after_confirmation(self):
        hook = """
CHECKS=0
verify_retirement_mount() {
  CHECKS=$((CHECKS + 1))
  (( CHECKS != 2 )) ||
    die 'Archive mount identity changed'
}
"""
        result = self.run_retire(
            f"RETIRE 1 {DRIVE}", hook=hook
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Archive mount identity changed",
            result.stderr
        )
        self.assertEqual(
            self.manifest.read_bytes(), self.before
        )
        self.assertFalse(self.receipts())

        print("PASS: Mount change after approval rejected")

    def test_09_mount_change_before_publication(self):
        hook = """
CHECKS=0
verify_retirement_mount() {
  CHECKS=$((CHECKS + 1))
  (( CHECKS != 3 )) ||
    die 'Archive mount identity changed'
}
"""
        result = self.run_retire(
            f"RETIRE 1 {DRIVE}", hook=hook
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Archive mount identity changed",
            result.stderr
        )
        self.assertEqual(
            self.manifest.read_bytes(), self.before
        )
        self.assertEqual(len(self.receipts()), 1)

        # An interrupted publication cannot authorize
        # a catalog deletion.
        with self.assertRaises(ValueError):
            authorized_retirements(
                self.folder,
                DRIVE,
                {"keep.mkv": A, "gone.mkv": B},
                {"keep.mkv"},
                parse_manifest,
            )

        print("PASS: Mount change before publication rejected")


    def test_10_wrong_expected_drive_rejected(self):
        result = self.run_retire(
            f"RETIRE 1 {DRIVE}",
            expected_drive="DIFFERENT_DISK",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "expected drive identity",
            result.stderr,
        )
        self.assertEqual(
            self.manifest.read_bytes(), self.before
        )
        self.assertFalse(self.receipts())
        self.assertFalse(self.snapshots())

        print("PASS: Wrong expected drive rejected")


    def test_11_manifest_changes_before_publication(self):
        hook = """
CHECKS=0
verify_retirement_mount() {
  CHECKS=$((CHECKS + 1))
  if (( CHECKS == 3 )); then
    printf '%064d  ./unexpected.mkv\\n' 0 >> "$MANIFEST"
  fi
}
"""
        result = self.run_retire(
            f"RETIRE 1 {DRIVE}",
            hook=hook,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Active manifest changed before retirement publication",
            result.stderr,
        )

        # The unexpected concurrent edit must not be
        # overwritten with the staged retirement manifest.
        active = self.manifest.read_text()
        self.assertIn("./unexpected.mkv", active)
        self.assertIn("./gone.mkv", active)

        # Published evidence alone never changes the
        # active manifest or authorizes a retirement.
        self.assertEqual(len(self.receipts()), 1)

        print("PASS: Concurrent manifest change rejected")

if __name__ == "__main__":
    unittest.main(verbosity=2)
