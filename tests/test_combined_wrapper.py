import os
import subprocess
import tempfile
import unittest
from pathlib import Path

WRAPPER = Path(
    "/work/host-tools/approved-sha-removals/"
    "cold-integrity-auto-sync.sh"
)

DRIVE = "TEST_DISK_SERIAL"

ENGINE = r'''#!/usr/bin/env bash
set -euo pipefail

case "$1" in
  register)
    echo "engine register" >> "$TEST_LOG"

    printf 'Device: %s\n' "$REG_ID"

    if [[ "${AMBIGUOUS:-0}" == "1" ]]; then
      echo 'Device: SECOND_DISK'
    fi

    case "$REG_STATE" in
      success)
        echo 'REGISTERED: 2 new files. Previous manifest snapshot: /test'
        ;;
      none)
        echo 'Nothing to register.'
        ;;
      cancel)
        echo 'Cancelled; no changes made.'
        ;;
      fail)
        echo 'ERROR: Registration failed.'
        exit 42
        ;;
    esac
    ;;

  retire)
    echo "engine retire expected=${COLD_EXPECTED_DEVICE_ID:-UNSET}" \
      >> "$TEST_LOG"

    printf 'Device: %s\n' "$RET_ID"

    if [[ "$RET_STATE" == "fail" ]]; then
      echo 'ERROR: Retirement failed.'
      exit 43
    fi

    if [[ "${IGNORE_ID_CHECK:-0}" != "1" &&
          "${COLD_EXPECTED_DEVICE_ID:-}" != "$RET_ID" ]]; then
      echo 'ERROR: Expected drive identity mismatch.'
      exit 44
    fi

    case "$RET_STATE" in
      success)
        echo 'RETIRED: 1 registered entries.'
        ;;
      none)
        echo 'No registered files need retirement.'
        ;;
      cancel)
        echo 'Cancelled; no changes made.'
        ;;
    esac
    ;;

  verify)
    echo "engine verify" >> "$TEST_LOG"
    printf 'Device: %s\n' "$REG_ID"
    echo 'VERIFY RESULT: PASS'
    ;;
esac
'''

CATALOG = r'''#!/usr/bin/env bash
set -euo pipefail
echo "catalog $1" >> "$TEST_LOG"
'''

HISTORY = r'''#!/usr/bin/env bash
set -euo pipefail
echo "history $1" >> "$TEST_LOG"
'''


class CombinedWrapperTests(unittest.TestCase):

    def run_case(
        self,
        *,
        registration="success",
        retirement="none",
        mode="register",
        retire_drive=DRIVE,
        ambiguous=False,
        ignore_id_check=False,
        expected_events,
        expected_rc=0,
    ):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            engine = root / "engine.sh"
            catalog = root / "catalog.sh"
            history = root / "history.sh"
            log = root / "events.log"

            engine.write_text(ENGINE)
            catalog.write_text(CATALOG)
            history.write_text(HISTORY)
            log.write_text("")

            env = os.environ.copy()

            env.update({
                "COLD_INTEGRITY_ENGINE": str(engine),
                "COLD_CATALOG_REFRESH_ENGINE": str(catalog),
                "COLD_HISTORY_SYNC_ENGINE": str(history),
                "TEST_LOG": str(log),
                "REG_ID": DRIVE,
                "RET_ID": retire_drive,
                "REG_STATE": registration,
                "RET_STATE": retirement,
                "AMBIGUOUS": "1" if ambiguous else "0",
                "IGNORE_ID_CHECK": (
                    "1" if ignore_id_check else "0"
                ),
            })

            result = subprocess.run(
                ["bash", str(WRAPPER), mode],
                env=env,
                input="",
                text=True,
                capture_output=True,
                timeout=20,
            )

            events = log.read_text().splitlines()

            self.assertEqual(
                result.returncode,
                expected_rc,
                result.stdout + "\n" + result.stderr,
            )

            self.assertEqual(
                events,
                expected_events,
                result.stdout + "\n" + result.stderr,
            )

    def test_01_expected_drive_passed_to_retirement(self):
        self.run_case(
            retirement="success",
            expected_events=[
                "engine register",
                f"engine retire expected={DRIVE}",
                f"catalog {DRIVE}",
                f"history {DRIVE}",
            ],
        )

    def test_02_retirement_without_new_registrations(self):
        self.run_case(
            registration="none",
            retirement="success",
            expected_events=[
                "engine register",
                f"engine retire expected={DRIVE}",
                f"catalog {DRIVE}",
                f"history {DRIVE}",
            ],
        )

    def test_03_no_changes_skip_catalog(self):
        self.run_case(
            registration="none",
            retirement="none",
            expected_events=[
                "engine register",
                f"engine retire expected={DRIVE}",
                f"history {DRIVE}",
            ],
        )

    def test_04_registration_failure_blocks_retirement(self):
        self.run_case(
            registration="fail",
            expected_rc=42,
            expected_events=[
                "engine register",
                f"history {DRIVE}",
            ],
        )

    def test_05_ambiguous_identity_blocks_retirement(self):
        self.run_case(
            ambiguous=True,
            expected_rc=71,
            expected_events=[
                "engine register",
            ],
        )

    def test_06_retirement_failure_blocks_catalog(self):
        self.run_case(
            retirement="fail",
            expected_rc=43,
            expected_events=[
                "engine register",
                f"engine retire expected={DRIVE}",
                f"history {DRIVE}",
            ],
        )

    def test_07_different_drive_blocks_catalog(self):
        self.run_case(
            retirement="success",
            retire_drive="DIFFERENT_DISK",
            ignore_id_check=True,
            expected_rc=71,
            expected_events=[
                "engine register",
                f"engine retire expected={DRIVE}",
            ],
        )

    def test_08_verify_never_calls_retirement(self):
        self.run_case(
            mode="verify",
            expected_events=[
                "engine verify",
                f"history {DRIVE}",
            ],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
