import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from app import parse_manifest
from retirement_approval import authorized_retirements

SOURCE = Path(
    "/work/host-tools/approved-sha-removals/integrity.sh"
)
WRAPPER = Path(
    "/work/host-tools/approved-sha-removals/"
    "cold-integrity-auto-sync.sh"
)

ID = "TEST_DISK_SERIAL"
GONE_HASH = "b" * 64


def digest(data):
    return hashlib.sha256(data).hexdigest()


def test_engine_source():
    """Replace only hardware-dependent setup in a disposable copy."""
    source = SOURCE.read_text()

    original_base = (
        "BASE='/mnt/user/Backups/cold_storage/devices'"
    )
    assert source.count(original_base) == 1

    source = source.replace(
        original_base,
        'BASE="${TEST_BASE:?}"',
        1,
    )

    start = source.index(
        "command -v flock >/dev/null"
    )
    end = source.index('DIR="$BASE/$ID"', start)

    fixture = '''
MOUNT="${TEST_MOUNT:?}"
ID="${TEST_DRIVE_ID:?}"
SERIAL="SERIAL"
MODEL="TEST_DISK"
SOURCE="/dev/null"
PARENT_NAME="test"
PARENT="/dev/null"
'''

    source = source[:start] + fixture + source[end:]

    guard_start = source.index(
        "# Retirement-only checks."
    )
    guard_end = source.index(
        'if [[ "$MODE" == retire ]]; then',
        guard_start,
    )

    # Mount/hardware-identity checks are simulated here.
    # Their production code is NOT changed.
    source = (
        source[:guard_start]
        + '''
init_retirement_mount() { :; }
verify_retirement_mount() {
  [[ -d "$MOUNT" ]] ||
    die 'Test archive mount disappeared.'
}

'''
        + source[guard_end:]
    )

    marker = 'BASE="${TEST_BASE:?}"'
    assert source.count(marker) == 1

    source = source.replace(
        marker,
        'printf "engine %s\\n" "$1" >> "${TEST_LOG:?}"\n'
        + marker,
        1,
    )

    result = subprocess.run(
        ["bash", "-n"],
        input=source,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr

    return source


ENGINE = test_engine_source()


class CreateEndToEndTests(unittest.TestCase):

    def run_case(
        self,
        *,
        new_file,
        missing_file,
        answers,
        expect_catalog,
        expect_retired,
    ):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "archive"
            base = root / "records" / "devices"
            folder = base / ID

            archive.mkdir()

            for name in (
                "manifests",
                "snapshots",
                "verification_logs",
            ):
                (folder / name).mkdir(parents=True)

            (folder / "device.json").write_text(
                json.dumps({
                    "device_id": ID,
                    "serial": "SERIAL",
                    "model": "TEST_DISK",
                }, indent=2)
            )

            keep_data = b"KEEP_TEST_CONTENT"
            new_data = b"NEW_TEST_CONTENT"

            (archive / "keep.mkv").write_bytes(keep_data)

            if new_file:
                (archive / "new.mkv").write_bytes(new_data)

            keep_hash = digest(keep_data)

            original = f"{keep_hash}  ./keep.mkv\n"

            if missing_file:
                original += (
                    f"{GONE_HASH}  ./gone.mkv\n"
                )

            manifest = (
                folder / "manifests" / "baseline.sha256"
            )
            manifest.write_text(original)

            engine = root / "engine.sh"
            catalog = root / "catalog.sh"
            history = root / "history.sh"
            log = root / "events.log"

            engine.write_text(ENGINE)
            log.write_text("")

            catalog.write_text(
                '#!/bin/bash\n'
                'printf "catalog %s\\n" "$1" >> "$TEST_LOG"\n'
            )
            history.write_text(
                '#!/bin/bash\n'
                'printf "history %s\\n" "$1" >> "$TEST_LOG"\n'
            )

            env = os.environ.copy()
            env.update({
                "TEST_BASE": str(base),
                "TEST_MOUNT": str(archive),
                "TEST_DRIVE_ID": ID,
                "TEST_LOG": str(log),
                "COLD_INTEGRITY_ENGINE": str(engine),
                "COLD_CATALOG_REFRESH_ENGINE": str(catalog),
                "COLD_HISTORY_SYNC_ENGINE": str(history),
            })

            if shutil.which("flock") is None:
                bin_dir = root / "bin"
                bin_dir.mkdir()
                stub = bin_dir / "flock"
                stub.write_text(
                    "#!/bin/sh\nexit 0\n"
                )
                stub.chmod(0o755)
                env["PATH"] = (
                    str(bin_dir) + ":" + env["PATH"]
                )

            result = subprocess.run(
                ["bash", str(WRAPPER), "register"],
                input=answers,
                text=True,
                capture_output=True,
                env=env,
                timeout=30,
            )

            self.assertEqual(
                result.returncode, 0,
                result.stdout + "\n" + result.stderr,
            )

            events = log.read_text().splitlines()

            expected = [
                "engine register",
                "engine retire",
            ]
            if expect_catalog:
                expected.append(f"catalog {ID}")
            expected.append(f"history {ID}")

            self.assertEqual(events, expected)

            active = dict(parse_manifest(manifest))

            self.assertEqual(
                active["keep.mkv"], keep_hash
            )

            self.assertEqual(
                (archive / "keep.mkv").read_bytes(),
                keep_data,
            )

            if new_file:
                self.assertEqual(
                    active["new.mkv"],
                    digest(new_data),
                )
                self.assertEqual(
                    (archive / "new.mkv").read_bytes(),
                    new_data,
                )

            receipts = list(
                (folder / "retirements").glob(
                    "retirement_*.tsv"
                )
            ) if (folder / "retirements").exists() else []

            snapshots = list(
                (folder / "snapshots").glob(
                    "baseline_retirement_*.sha256"
                )
            )

            if expect_retired:
                self.assertNotIn("gone.mkv", active)
                self.assertEqual(len(receipts), 1)
                self.assertEqual(len(snapshots), 1)

                approved = authorized_retirements(
                    folder,
                    ID,
                    {
                        "keep.mkv": keep_hash,
                        "gone.mkv": GONE_HASH,
                    },
                    set(active),
                    parse_manifest,
                )
                self.assertEqual(
                    approved, {"gone.mkv"}
                )
            else:
                self.assertFalse(receipts)
                self.assertFalse(snapshots)

                if missing_file:
                    self.assertEqual(
                        active["gone.mkv"],
                        GONE_HASH,
                    )

    def test_01_register_and_retire(self):
        self.run_case(
            new_file=True,
            missing_file=True,
            answers=f"REGISTER\nRETIRE 1 {ID}\n",
            expect_catalog=True,
            expect_retired=True,
        )

    def test_02_retire_without_new_files(self):
        self.run_case(
            new_file=False,
            missing_file=True,
            answers=f"RETIRE 1 {ID}\n",
            expect_catalog=True,
            expect_retired=True,
        )

    def test_03_register_without_missing_files(self):
        self.run_case(
            new_file=True,
            missing_file=False,
            answers="REGISTER\n",
            expect_catalog=True,
            expect_retired=False,
        )

    def test_04_no_changes(self):
        self.run_case(
            new_file=False,
            missing_file=False,
            answers="",
            expect_catalog=False,
            expect_retired=False,
        )

    def test_05_decline_retirement(self):
        self.run_case(
            new_file=False,
            missing_file=True,
            answers="CANCEL\n",
            expect_catalog=False,
            expect_retired=False,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
