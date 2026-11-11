"""Synthetic tests for the development SHA-256 progress writer.

No real archive mount, device record, or installed engine is accessed.
"""

import datetime
import hashlib
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

from verification_progress import parse_progress


ENGINE = Path(
    "/work/host-tools/approved-sha-removals/integrity.sh"
)


def source_sections():
    source = ENGINE.read_text(encoding="utf-8")

    begin = "# BEGIN VERIFY PROGRESS REPORTING\n"
    end = "# END VERIFY PROGRESS REPORTING\n"

    assert source.count(begin) == 1
    assert source.count(end) == 1

    reporter = (
        begin
        + source.split(begin, 1)[1].split(end, 1)[0]
        + end
    )

    assert source.count("cleanup() {\n") == 1
    assert source.count("trap cleanup EXIT\n") == 1

    cleanup = (
        "cleanup() {\n"
        + source.split("cleanup() {\n", 1)[1]
        .split("trap cleanup EXIT\n", 1)[0]
        + "trap cleanup EXIT\n"
    )

    marker = (
        "# Full verification includes untracked-file "
        "detection, missing files and\n"
    )

    assert source.count(marker) == 1

    verification = marker + source.split(marker, 1)[1]

    assert verification.rstrip().endswith(
        '[[ "$RESULT" == PASS ]]'
    )

    return reporter, cleanup, verification


class EngineProgressTests(unittest.TestCase):

    def run_case(
        self, registered, files, *,
        interrupt=False,
        blocked=False,
        read_error=False,
    ):
        reporter, cleanup, verification = source_sections()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            mount = root / "synthetic-archive"
            mount.mkdir()

            records = root / "synthetic-device"
            logs = records / "verification_logs"
            logs.mkdir(parents=True)

            # Only synthetic source files are created here.
            for name, content in files.items():
                (mount / name).write_bytes(content)

            inventory = root / "synthetic-inventory"
            inventory.write_bytes(
                b"".join(
                    b"./" + name.encode("utf-8") + b"\0"
                    for name in files
                )
            )

            if blocked:
                # Intentionally block progress publication.
                (logs / "verify_progress.json").mkdir()

            prefix = [
                "#!/usr/bin/env bash",
                "set -Eeuo pipefail",
                "umask 022",
                "MODE=verify",
                f"MOUNT={shlex.quote(str(mount))}",
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
            ]

            for name, checksum in registered.items():
                prefix.append(
                    f'KNOWN["./{name}"]='
                    f'{shlex.quote(checksum)}'
                )

            prefix.extend([
                "issue() {",
                '  local kind="$1" path="$2"',
                "  printf '%s\\t%s\\t%s\\n' "
                '"$STAMP" "$kind" "$path" >> "$ISSUES"',
                '  if [[ "${TEST_INTERRUPT_ON_ISSUE:-0}" '
                '== "1" ]]; then exit 35; fi',
                "}",
                "record_run() {",
                "  printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "
                '"$STAMP" "$1" "$2" "$3" "$4" "$5" '
                '>> "$RUNS"',
                "}",
            ])

            runner = root / "synthetic-runner.sh"
            runner.write_text(
                "\n".join(prefix)
                + "\n" + reporter + cleanup + verification,
                encoding="utf-8",
            )

            syntax = subprocess.run(
                ["bash", "-n", str(runner)],
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertEqual(
                syntax.returncode, 0, syntax.stderr
            )

            env = dict(os.environ)

            if interrupt:
                env["TEST_INTERRUPT_ON_ISSUE"] = "1"

            if read_error:
                # Load a test-only Bash function into the
                # verification runner. This does not depend
                # on executing scripts from the tmpfs mount.
                function_source = (
                    root / "synthetic-sha-function.sh"
                )

                function_source.write_text(
                    'sha256sum() {\n'
                    '  printf "%s\\n" "$*" >> '
                    '"$TEST_SHA_SHIM_LOG"\n'
                    '  local argument\n'
                    '  for argument in "$@"; do\n'
                    '    if [[ "${argument##*/}" == '
                    '"read_error" ]]; then\n'
                    '      return 17\n'
                    '    fi\n'
                    '  done\n'
                    '  command sha256sum "$@"\n'
                    '}\n',
                    encoding="utf-8",
                )

                shim_log = root / "sha-shim-calls.log"

                env["BASH_ENV"] = str(function_source)
                env["TEST_SHA_SHIM_LOG"] = str(shim_log)
                env["TEST_READ_ERROR_PATH"] = str(
                    mount / "read_error"
                )

                # Independently verify that the same Bash
                # loading mechanism produces a read error.
                probe = subprocess.run(
                    [
                        "bash",
                        "-c",
                        'sha256sum -- "$TEST_READ_ERROR_PATH"',
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                self.assertEqual(
                    probe.returncode,
                    17,
                    probe.stderr,
                )

                self.assertIn(
                    "/read_error",
                    shim_log.read_text(encoding="utf-8"),
                )

                # Keep only actual verification-runner calls
                # for the assertion below.
                shim_log.write_text(
                    "",
                    encoding="utf-8",
                )

            result = subprocess.run(
                ["bash", str(runner)],
                env=env,
                capture_output=True,
                text=True,
                timeout=20,
            )

            if read_error:
                self.assertTrue(
                    shim_log.is_file(),
                    "Synthetic SHA invocation log missing",
                )

                calls = shim_log.read_text(
                    encoding="utf-8",
                )

                self.assertIn(
                    "/read_error",
                    calls,
                    "Verification runner did not invoke "
                    "the simulated read-error shim",
                )

            runs_file = logs / "runs.tsv"

            runs = (
                runs_file.read_text(encoding="utf-8")
                if runs_file.exists()
                else ""
            )

            issues_file = logs / "issues.tsv"

            issues = (
                issues_file.read_text(encoding="utf-8")
                if issues_file.exists()
                else ""
            )

            progress_file = logs / "verify_progress.json"

            if progress_file.is_file():
                progress = parse_progress(
                    progress_file.read_bytes(),
                    now=datetime.datetime.now(
                        datetime.timezone.utc
                    ),
                )
            else:
                progress = None

            remaining_temporary_files = list(
                logs.glob(".verify_progress.*")
            )

            actual_files = {
                name: (mount / name).read_bytes()
                for name in files
            }

            return (
                result,
                runs,
                issues,
                progress,
                actual_files,
                remaining_temporary_files,
            )

    def test_success_preserves_archive_and_records_pass(self):
        contents = {
            "good": b"good",
            "other": b"other",
        }

        registered = {
            name: hashlib.sha256(content).hexdigest()
            for name, content in contents.items()
        }

        result, runs, issues, progress, actual, tmp = (
            self.run_case(registered, contents)
        )

        self.assertEqual(
            result.returncode, 0, result.stderr
        )

        self.assertEqual(actual, contents)
        self.assertEqual(issues, "")
        self.assertEqual(tmp, [])

        self.assertIn(
            "\tverify\tPASS\t2\t0\t0\n",
            runs,
        )

        self.assertEqual(progress["phase"], "finished")
        self.assertEqual(progress["total"], 2)
        self.assertEqual(progress["processed"], 2)
        self.assertEqual(progress["hashed"], 2)
        self.assertEqual(progress["issues"], 0)
        self.assertEqual(progress["percent"], 100)

        # A progress record is not itself proof of PASS.
        self.assertNotIn("outcome", progress)

    def test_missing_mismatch_read_error_and_unregistered(self):
        contents = {
            "good": b"good",
            "changed": b"changed",
            "read_error": b"unreadable-test",
            "extra": b"unregistered",
        }

        registered = {
            "good": hashlib.sha256(b"good").hexdigest(),
            "changed": hashlib.sha256(
                b"original"
            ).hexdigest(),
            "read_error": hashlib.sha256(
                b"unreadable-test"
            ).hexdigest(),
            "missing": hashlib.sha256(
                b"absent"
            ).hexdigest(),
        }

        result, runs, issues, progress, actual, tmp = (
            self.run_case(
                registered,
                contents,
                read_error=True,
            )
        )

        self.assertEqual(result.returncode, 1)
        self.assertEqual(actual, contents)
        self.assertEqual(tmp, [])

        self.assertIn(
            "\tverify\tFAIL\t4\t1\t4\n",
            runs,
        )

        for kind in (
            "MISSING",
            "READ_ERROR",
            "HASH_MISMATCH",
            "UNREGISTERED",
        ):
            self.assertIn(
                "\t" + kind + "\t",
                issues,
            )

        self.assertEqual(progress["phase"], "finished")
        self.assertEqual(progress["total"], 4)
        self.assertEqual(progress["processed"], 4)
        self.assertEqual(progress["hashed"], 2)
        self.assertEqual(progress["issues"], 4)
        self.assertEqual(progress["unregistered"], 1)
        self.assertEqual(progress["percent"], 100)

        # All files processed, but permanent result is FAIL.
        self.assertNotIn("outcome", progress)

    def test_interruption_remains_incomplete(self):
        registered = {
            "missing": hashlib.sha256(
                b"absent"
            ).hexdigest()
        }

        result, runs, issues, progress, actual, tmp = (
            self.run_case(
                registered,
                {},
                interrupt=True,
            )
        )

        self.assertEqual(result.returncode, 35)
        self.assertEqual(actual, {})
        self.assertEqual(tmp, [])

        self.assertIn(
            "\tverify\tINCOMPLETE\t1\t0\t-1\n",
            runs,
        )

        self.assertIn("\tMISSING\t", issues)

        self.assertEqual(
            progress["phase"],
            "interrupted",
        )

        self.assertEqual(progress["processed"], 0)
        self.assertEqual(progress["total"], 1)
        self.assertNotIn("outcome", progress)

    def test_progress_write_failure_does_not_change_result(self):
        contents = {"good": b"good"}

        registered = {
            "good": hashlib.sha256(
                b"good"
            ).hexdigest()
        }

        result, runs, issues, progress, actual, tmp = (
            self.run_case(
                registered,
                contents,
                blocked=True,
            )
        )

        self.assertEqual(
            result.returncode, 0, result.stderr
        )

        self.assertIn(
            "\tverify\tPASS\t1\t0\t0\n",
            runs,
        )

        self.assertEqual(actual, contents)
        self.assertEqual(issues, "")
        self.assertIsNone(progress)
        self.assertEqual(tmp, [])

        self.assertEqual(
            result.stderr.count(
                "WARNING: Unable to publish"
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()
