"""Exercise real progress heartbeats using synthetic files only."""

import hashlib
import os
import shlex
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from test_verification_progress_engine import source_sections
from verification_progress import read_progress


class LongFileHeartbeatTests(unittest.TestCase):

    def run_slow_hash(self, fail=False):
        reporter, cleanup, verification = source_sections()

        # Modify only a disposable synthetic runner.
        # Never modify development or installed integrity.sh.
        old_interval = "PROGRESS_HEARTBEAT_SECONDS=20\n"
        old_threshold = "PROGRESS_HEARTBEAT_MIN_BYTES=67108864\n"

        self.assertEqual(reporter.count(old_interval), 1)
        self.assertEqual(reporter.count(old_threshold), 1)

        reporter = reporter.replace(
            old_interval,
            "PROGRESS_HEARTBEAT_SECONDS=1\n",
            1,
        )

        reporter = reporter.replace(
            old_threshold,
            "PROGRESS_HEARTBEAT_MIN_BYTES=1\n",
            1,
        )

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)

            archive = root / "synthetic-archive"
            archive.mkdir()

            media = archive / "large.mkv"
            original = b"synthetic-video-checksum-test"
            media.write_bytes(original)

            records = root / "synthetic-device"
            logs = records / "verification_logs"
            logs.mkdir(parents=True)

            inventory = root / "inventory"
            inventory.write_bytes(b"./large.mkv\0")

            expected_hash = hashlib.sha256(
                original
            ).hexdigest()

            prefix = [
                "#!/usr/bin/env bash",
                "set -Eeuo pipefail",
                "umask 022",
                "MODE=verify",
                f"MOUNT={shlex.quote(str(archive))}",
                f"DIR={shlex.quote(str(records))}",
                'STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"',
                'RUNS="$DIR/verification_logs/runs.tsv"',
                'ISSUES="$DIR/verification_logs/issues.tsv"',
                f"ALL_LIST={shlex.quote(str(inventory))}",
                f"NEW_LIST={shlex.quote(str(root / 'new'))}",
                "STAGED=''",
                "RESCAN=''",
                "RECEIPT_TMP=''",
                "COMPLETED=0",
                "declare -A KNOWN=()",
                f'KNOWN["./large.mkv"]={expected_hash}',
                'issue() {',
                '  printf "%s\\t%s\\t%s\\n" '
                '"$STAMP" "$1" "$2" >> "$ISSUES"',
                '}',
                'record_run() {',
                '  printf "%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n" '
                '"$STAMP" "$1" "$2" "$3" "$4" "$5" '
                '>> "$RUNS"',
                '}',
            ]

            runner = root / "synthetic-runner.sh"
            runner.write_text(
                "\n".join(prefix)
                + "\n"
                + reporter
                + cleanup
                + verification,
                encoding="utf-8",
            )

            syntax = subprocess.run(
                ["bash", "-n", str(runner)],
                capture_output=True,
                text=True,
                timeout=5,
            )

            self.assertEqual(
                syntax.returncode,
                0,
                syntax.stderr,
            )

            # The test-only SHA function intentionally takes
            # four seconds to process the synthetic video.
            # The real checksum command still runs on success.
            shim = root / "synthetic-sha-function.sh"
            shim.write_text(
                'sha256sum() {\n'
                '  if [[ "${2:-}" == */large.mkv ]]; then\n'
                '    printf "started\\n" > "$TEST_HASH_STARTED"\n'
                '    sleep 4\n'
                '    if [[ "${TEST_HASH_FAIL:-0}" == "1" ]]; then\n'
                '      return 17\n'
                '    fi\n'
                '  fi\n'
                '  command sha256sum "$@"\n'
                '}\n',
                encoding="utf-8",
            )

            started_file = root / "hash-started"

            env = dict(os.environ)
            env["BASH_ENV"] = str(shim)
            env["TEST_HASH_STARTED"] = str(started_file)
            env["TEST_HASH_FAIL"] = "1" if fail else "0"

            process = subprocess.Popen(
                ["bash", str(runner)],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )

            observations = []

            try:
                deadline = time.monotonic() + 12

                while (
                    process.poll() is None
                    and time.monotonic() < deadline
                ):
                    progress = read_progress(records)

                    if progress and progress["phase"] == "running":
                        observations.append(progress)

                    time.sleep(0.15)

                self.assertIsNotNone(
                    process.poll(),
                    "Synthetic SHA operation exceeded timeout",
                )

                stdout, stderr = process.communicate(
                    timeout=5
                )

            finally:
                if process.poll() is None:
                    os.killpg(
                        process.pid,
                        signal.SIGKILL,
                    )
                    process.communicate(timeout=5)

            self.assertTrue(
                started_file.is_file(),
                "Slow synthetic SHA function was not invoked",
            )

            self.assertGreaterEqual(
                len(observations),
                2,
                "No running-progress samples were observed",
            )

            timestamps = {
                item["updated_at"]
                for item in observations
            }

            self.assertGreaterEqual(
                len(timestamps),
                2,
                "Heartbeat did not advance the timestamp: "
                + repr(sorted(timestamps)),
            )

            for item in observations:
                self.assertEqual(item["total"], 1)
                self.assertEqual(item["processed"], 0)
                self.assertEqual(item["hashed"], 0)
                self.assertEqual(item["issues"], 0)
                self.assertEqual(item["percent"], 0)

            progress = read_progress(records)

            self.assertIsNotNone(progress)
            self.assertEqual(progress["phase"], "finished")
            self.assertEqual(progress["processed"], 1)
            self.assertEqual(progress["percent"], 100)

            expected_exit = 1 if fail else 0
            expected_hashed = 0 if fail else 1
            expected_issues = 1 if fail else 0
            expected_outcome = "FAIL" if fail else "PASS"

            self.assertEqual(
                process.returncode,
                expected_exit,
                stderr + stdout,
            )

            self.assertEqual(
                progress["hashed"],
                expected_hashed,
            )

            self.assertEqual(
                progress["issues"],
                expected_issues,
            )

            runs = (
                logs / "runs.tsv"
            ).read_text(encoding="utf-8")

            self.assertIn(
                "\tverify\t"
                + expected_outcome
                + "\t1\t0\t"
                + str(expected_issues)
                + "\n",
                runs,
            )

            if fail:
                issues = (
                    logs / "issues.tsv"
                ).read_text(encoding="utf-8")

                self.assertIn("\tREAD_ERROR\t", issues)

            self.assertEqual(
                media.read_bytes(),
                original,
                "Synthetic archive file was modified",
            )

            final_file = logs / "verify_progress.json"
            final_bytes = final_file.read_bytes()

            # The test heartbeat runs once per second.
            # After verification finishes, no worker may
            # overwrite or refresh the final state.
            time.sleep(1.5)

            self.assertEqual(
                final_file.read_bytes(),
                final_bytes,
                "Heartbeat modified terminal progress metadata",
            )

            self.assertEqual(
                list(logs.glob(".verify_progress.*")),
                [],
                "Temporary progress files were not cleaned",
            )

            print(
                "PASS: Slow hash returned",
                expected_outcome,
                "| heartbeat timestamps:",
                len(timestamps),
                "| final processed:",
                progress["processed"],
                "| final hashed:",
                progress["hashed"],
            )

    def test_slow_successful_hash_heartbeats_and_stops(self):
        self.run_slow_hash(fail=False)

    def test_slow_failed_hash_heartbeats_and_stops(self):
        self.run_slow_hash(fail=True)


if __name__ == "__main__":
    unittest.main()
