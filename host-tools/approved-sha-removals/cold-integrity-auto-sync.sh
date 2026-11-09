#!/usr/bin/env bash
# Integrity wrapper: catalog successful registrations before syncing history.
# Engine paths are supplied by the installed launchers.
set -uo pipefail

if (( $# != 1 )) || [[ "$1" != register && "$1" != verify ]]; then
  printf 'Usage: cold-integrity-auto-sync.sh register|verify\n' >&2
  exit 64
fi

mode="$1"
engine="${COLD_INTEGRITY_ENGINE:-}"
sync_engine="${COLD_HISTORY_SYNC_ENGINE:-}"
catalog_engine="${COLD_CATALOG_REFRESH_ENGINE:-}"

for target in "$engine" "$sync_engine" "$catalog_engine"; do
  if [[ "$target" != /* || ! -f "$target" || -L "$target" ]]; then
    printf 'STOP: An absolute, regular, non-symlink engine path is required.\n' >&2
    exit 65
  fi
done

capture="$(mktemp "${TMPDIR:-/tmp}/cold-history-sync.XXXXXXXX")" || exit 73
retire_capture=''

cleanup() {
  rm -f -- "$capture"
  if [[ -n "$retire_capture" ]]; then
    rm -f -- "$retire_capture"
  fi
}
trap cleanup EXIT

# Preserve interactive stdin for the original engine.
# Tee captures output so the engine's drive ID can be identified.
bash "$engine" "$mode" 2>&1 | tee "$capture"
statuses=("${PIPESTATUS[@]}")
engine_rc="${statuses[0]}"
tee_rc="${statuses[1]}"
retire_rc=0

# Resolve the first operation's drive identity BEFORE
# initiating retirement. The second operation must agree.
if [[ "$mode" == register ]] &&
   (( engine_rc == 0 && tee_rc == 0 )); then

  mapfile -t expected_ids < <(
    sed -nE \
      's/^Device:[[:space:]]+([A-Za-z0-9._-]+)[[:space:]]*$/\1/p' \
      "$capture"
  )

  if (( ${#expected_ids[@]} != 1 )) ||
     [[ ! "${expected_ids[0]:-}" =~ ^[A-Za-z0-9._-]{1,256}$ ]]; then
    printf 'STOP: Registration drive identity is ambiguous.\n' >&2
    exit 71
  fi
fi

# Only cold-sha256-create reaches this additional review.
# If registration failed, do not offer retirement.
if [[ "$mode" == register ]] &&
   (( engine_rc == 0 && tee_rc == 0 )); then

  retire_capture="$(
    mktemp "${TMPDIR:-/tmp}/cold-retire-sync.XXXXXXXX"
  )" || exit 73

  printf '\n=== Optional registered-file retirement review ===\n'

  COLD_EXPECTED_DEVICE_ID="${expected_ids[0]}" \
    bash "$engine" retire 2>&1 | tee "$retire_capture"
  retire_status=("${PIPESTATUS[@]}")

  if (( retire_status[1] != 0 )); then
    printf 'STOP: Unable to capture retirement output.\n' >&2
    exit 72
  fi

  retire_rc="${retire_status[0]}"
fi

printf '\nOriginal SHA-256 command exit code: %s\n' "$engine_rc"

if (( tee_rc != 0 )); then
  printf 'HISTORY SYNC SKIPPED: unable to capture command output.\n' >&2
  if (( engine_rc != 0 )); then exit "$engine_rc"; fi
  exit 72
fi

mapfile -t ids < <(
  sed -nE 's/^Device:[[:space:]]+([A-Za-z0-9._-]+)[[:space:]]*$/\1/p' "$capture"
)

if (( ${#ids[@]} != 1 )) || (( ${#ids[0]} > 256 )); then
  printf 'HISTORY SYNC SKIPPED: no unique valid drive identity in command output.\n' >&2
  if (( engine_rc != 0 )); then exit "$engine_rc"; fi
  exit 71
fi

# The two host operations must identify the same physical disk.
# A missing, malformed, or different retirement identity
# prevents any catalog mutation.
if [[ "$mode" == register && -n "$retire_capture" ]]; then

  mapfile -t retire_ids < <(
    sed -nE       's/^Device:[[:space:]]+([A-Za-z0-9._-]+)[[:space:]]*$/\1/p'       "$retire_capture"
  )

  if (( ${#retire_ids[@]} != 1 )) ||
     [[ "${retire_ids[0]}" != "${ids[0]}" ]]; then
    printf 'STOP: Retirement drive identity mismatch.\n' >&2
    exit 71
  fi

  if (( retire_rc != 0 )); then
    printf 'RETIREMENT REVIEW FAILED: Catalog refresh skipped.\n' >&2
    engine_rc="$retire_rc"
  fi
fi

# A new drive may not yet exist in SQLite. A successful registration receipt
# permits a targeted catalog refresh, which creates its row and imports history.
# No-change/cancelled runs still avoid a physical rescan.
refresh_registered_catalog() (
# Only the confirmed registration receipt allows a disk scan.
# NO_CHANGES and cancellations must not wake the archive again.
mapfile -t counts < <(
  sed -nE 's/^REGISTERED: ([0-9]+) new files\..*$/\1/p' "$capture"
)

mapfile -t retired_counts < <(
  if [[ -n "$retire_capture" ]]; then
    sed -nE \
      's/^RETIRED: ([0-9]+) registered entries\..*$/\1/p' \
      "$retire_capture"
  fi
)

if (( ${#counts[@]} > 1 || ${#retired_counts[@]} > 1 )); then
  printf 'CATALOG REFRESH FAILED: Ambiguous operation receipts.\n' >&2
  exit 68
fi

registered=0
retired=0

if (( ${#counts[@]} == 1 )); then
  [[ "${counts[0]}" =~ ^[1-9][0-9]*$ ]] || {
    printf 'CATALOG REFRESH FAILED: Invalid registration count.\n' >&2
    exit 68
  }
  registered="${counts[0]}"
fi

if (( ${#retired_counts[@]} == 1 )); then
  [[ "${retired_counts[0]}" =~ ^[1-9][0-9]*$ ]] || {
    printf 'CATALOG REFRESH FAILED: Invalid retirement count.\n' >&2
    exit 68
  }
  retired="${retired_counts[0]}"
fi

# Registration and retirement are independent decisions.
# Either successful operation permits one targeted refresh.
if (( registered == 0 && retired == 0 )); then

  if grep -Fxq 'Nothing to register.' "$capture" ||
     grep -Fxq 'Cancelled; no changes made.' "$capture"; then
    printf 'CATALOG REFRESH: SKIPPED (no manifest changes)\n'
    exit 0
  fi

  printf 'CATALOG REFRESH FAILED: No confirmed changes.\n' >&2
  exit 68
fi

printf '\n=== Targeted physical catalog refresh ===\n'
printf 'Registered new files: %s\n' "$registered"
printf 'Retired SHA registrations: %s\n' "$retired"
printf 'Selected drive: %s\n' "${ids[0]}"

if bash "$catalog_engine" "${ids[0]}"; then
  printf 'CATALOG REFRESH: PASS\n'
else
  catalog_rc=$?
  printf 'CATALOG REFRESH: FAILED (exit %s); registration remains completed.\n' "$catalog_rc" >&2
  exit 69
fi

exit 0
)

catalog_rc=0
if (( engine_rc == 0 )) && [[ "$mode" == register ]]; then
  if grep -Eq '^REGISTERED: [1-9][0-9]* new files\.' "$capture"; then
    printf '\nCHECKSUM REGISTRATION: COMPLETE — checksums saved.\n'
  fi
  if refresh_registered_catalog; then
    catalog_rc=0
  else
    catalog_rc=$?
  fi
elif [[ "$mode" == verify ]]; then
  printf 'CATALOG REFRESH: SKIPPED (verification only)\n'
fi

printf '\n=== Offline catalog history synchronization ===\n'

if bash "$sync_engine" "${ids[0]}"; then
  printf 'HISTORY SYNC: PASS\n'
  sync_rc=0
else
  sync_rc=$?
  printf 'CATALOG HISTORY SYNC: INCOMPLETE (exit %s); the integrity result above is unchanged.\n' "$sync_rc" >&2
fi


if (( engine_rc != 0 )); then exit "$engine_rc"; fi
if (( catalog_rc != 0 || sync_rc != 0 )); then
  printf '\nCatalog synchronization needs attention; do not repeat hashing just to repair synchronization.\n' >&2
  printf 'Use Refresh catalog, then retry history synchronization for the drive shown above.\n' >&2
  if (( catalog_rc != 0 )); then exit "$catalog_rc"; fi
  exit 70
fi
printf '\nOperation and catalog history synchronization completed.\n'
exit 0
