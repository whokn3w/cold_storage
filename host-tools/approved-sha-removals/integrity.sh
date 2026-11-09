#!/bin/bash
# Pucksly cold storage integrity manager (manual registration and verification).
# READ-ONLY toward the mounted archive disk. Writes metadata only under Backups.
set -Eeuo pipefail
# Metadata readable by catalog and file browsers; root retains write ownership.
umask 022
export LC_ALL=C
BASE='/mnt/user/Backups/cold_storage/devices'
ROOT='/mnt/disks'
usage() { printf 'Usage: %s register|verify|status|retire-preview|retire\n' "$0"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ $# -eq 1 ]] || { usage; exit 2; }
MODE="$1"
[[ "$MODE" == register || "$MODE" == verify || "$MODE" == status || "$MODE" == retire-preview || "$MODE" == retire ]] || { usage; exit 2; }
command -v flock >/dev/null && command -v sha256sum >/dev/null && command -v findmnt >/dev/null && command -v lsblk >/dev/null || die 'Required tools unavailable.'
mapfile -t MOUNTS < <(findmnt -rn -o TARGET | grep "^${ROOT}/" || true)
[[ ${#MOUNTS[@]} -eq 1 ]] || die 'Mount exactly one Unassigned Devices disk under /mnt/disks before running.'
MOUNT="${MOUNTS[0]}"
[[ "$(dirname "$MOUNT")" == "$ROOT" ]] || die 'Unexpected nested mount.'
SOURCE="$(findmnt -rn -o SOURCE --mountpoint "$MOUNT")"
[[ -b "$SOURCE" ]] || die 'Mount is not backed by a block device.'
PARENT_NAME="$(lsblk -dn -o PKNAME "$SOURCE" | xargs)"
[[ -n "$PARENT_NAME" ]] || die 'Cannot resolve physical parent disk.'
PARENT="/dev/$PARENT_NAME"
SERIAL="$(lsblk -dn -o SERIAL "$PARENT" | xargs)"
MODEL="$(lsblk -dn -o MODEL "$PARENT" | xargs)"
[[ -n "$SERIAL" && -n "$MODEL" ]] || die 'Cannot read disk model and serial.'
ID="${MODEL// /_}_${SERIAL}"
[[ "$(basename "$MOUNT")" == "$ID" ]] || die 'Mount name does not match physical disk identity.'
DIR="$BASE/$ID"
META="$DIR/device.json"
[[ -f "$META" ]] || die 'Drive is not registered. Run cold-register.sh first.'
grep -Fq "\"serial\": \"$SERIAL\"" "$META" || die 'Registered serial mismatch.'
grep -Fq "\"device_id\": \"$ID\"" "$META" || die 'Registered device ID mismatch.'
MANIFEST="$DIR/manifests/baseline.sha256"
[[ -f "$MANIFEST" ]] || die 'Existing baseline manifest missing. Do not generate a new one automatically.'
mkdir -p "$DIR/verification_logs" "$DIR/snapshots"
exec 9>"$DIR/.integrity.lock"
flock -n 9 || die 'Another integrity operation is running for this disk.'
RUNS="$DIR/verification_logs/runs.tsv"
ISSUES="$DIR/verification_logs/issues.tsv"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# Manifests use the standard GNU sha256sum text format. Reject filenames that
# cannot be represented unambiguously by this deliberately conservative parser.
# Simpler explicit check (avoid shell glob ambiguities).
safe_path() {
  local p="$1" relative
  [[ "$p" == ./* && "$p" != './' ]] || return 1
  relative="${p#./}"
  [[ -n "$relative" && "$relative" != /* ]] || return 1
  [[ "/$relative/" != *'/../'* && "/$relative/" != *'/./'* ]] || return 1
  [[ "$p" != *$'\n'* && "$p" != *$'\r'* && "$p" != *$'\t'* && "$p" != *'\'* ]] || return 1
  return 0
}

declare -A KNOWN=()
load_manifest() {
  local line hash path
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ ${#line} -ge 67 ]] || die 'Malformed manifest line; refusing to modify or trust it.'
    hash="${line:0:64}"
    [[ "$hash" =~ ^[0-9a-f]{64}$ && "${line:64:2}" == '  ' ]] || die 'Unsupported or malformed checksum record; manual review required.'
    path="${line:66}"
    safe_path "$path" || die 'Manifest contains an unsupported or unsafe filename.'
    [[ ! -v KNOWN["$path"] ]] || die "Duplicate manifest entry: $path"
    KNOWN["$path"]="$hash"
  done < "$MANIFEST"
}
# Record issues in append-only tab-separated history. Filenames containing
# tabs/newlines are refused, so TSV remains unambiguous.
issue() {
  local kind="$1" path="$2"
  printf '%s\t%s\t%s\n' "$STAMP" "$kind" "$path" >> "$ISSUES"
  printf '  %-18s %s\n' "$kind" "$path"
}
record_run() {
  local action="$1" outcome="$2" tracked="$3" new="$4" problems="$5"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$STAMP" "$action" "$outcome" "$tracked" "$new" "$problems" >> "$RUNS"
}
load_manifest
printf 'Device: %s\nMount:  %s\nTracked files: %d\n\n' "$ID" "$MOUNT" "${#KNOWN[@]}"
if [[ "$MODE" == status ]]; then
  echo 'Recent operations (UTC | action | result | tracked | new/untracked | problems):'
  if [[ -s "$RUNS" ]]; then tail -n 10 "$RUNS"; else echo '  No operations recorded yet.'; fi
  echo
  echo 'Recent detected issues (historical, not necessarily unresolved):'
  if [[ -s "$ISSUES" ]]; then tail -n 15 "$ISSUES"; else echo '  No issues recorded yet.'; fi
  printf '\nHistory: %s\n' "$DIR/verification_logs"
  exit 0
fi
# Snapshot actual on-disk file paths, rejecting special characters rather than
# silently producing misleading manifests or logs.
ALL_LIST="$(mktemp "$DIR/manifests/.paths.XXXXXXXX")"
NEW_LIST="$(mktemp "$DIR/manifests/.new.XXXXXXXX")"
STAGED=''
RESCAN=''
RECEIPT_TMP=''
COMPLETED=0
cleanup() {
  local rc=$?
  if (( COMPLETED == 0 )) && [[ "$MODE" != retire-preview && "$MODE" != retire ]]; then
    printf '%s\t%s\tINCOMPLETE\t%s\t0\t-1\n' "$STAMP" "$MODE" "${#KNOWN[@]}" >> "$RUNS" || true
  fi
  rm -f -- "$ALL_LIST" "$NEW_LIST"
  [[ -z "$STAGED" ]] || rm -f -- "$STAGED"
  [[ -z "$RESCAN" ]] || rm -f -- "$RESCAN"
  [[ -z "$RECEIPT_TMP" ]] || rm -f -- "$RECEIPT_TMP"
  return "$rc"
}
trap cleanup EXIT
(
  cd "$MOUNT"
  find . -type f -print0 > "$ALL_LIST"
)
# Validate every path before changing the manifest.
while IFS= read -r -d '' path; do
  safe_path "$path" || die 'A filename contains a backslash, tab or newline; cannot safely record it. No changes made.'
  [[ ! -L "$MOUNT/${path#./}" ]] || die 'Symbolic link encountered; no changes made.'
  if [[ ! -v KNOWN["$path"] ]]; then printf '%s\0' "$path" >> "$NEW_LIST"; fi
done < "$ALL_LIST"
if [[ "$MODE" == retire-preview ]]; then
  declare -a MISSING=()

  for path in "${!KNOWN[@]}"; do
    FILE="$MOUNT/${path#./}"

    if [[ -L "$FILE" ]]; then
      die "Registered path is a symbolic link: $path"
    fi

    if [[ ! -e "$FILE" ]]; then
      MISSING+=("$path")
    elif [[ ! -f "$FILE" ]]; then
      die "Registered path is not a regular file: $path"
    fi
  done

  printf '\nMissing SHA-registered files: %d\n' "${#MISSING[@]}"

  if (( ${#MISSING[@]} > 0 )); then
    printf '%s\n' "${MISSING[@]}" | LC_ALL=C sort
  fi

  printf '\nRETIRE PREVIEW ONLY\n'
  printf 'No SHA-256 records were changed.\n'
  printf 'No files were retired or approved.\n'

  COMPLETED=1
  exit 0
fi

# Retirement-only checks. Registration and verification
# retain their existing production behavior.
init_retirement_mount() {
  RETIRE_MOUNT_ID="$(
    findmnt -rn -o ID --mountpoint "$MOUNT"
  )" || die 'Cannot identify archive mount.'

  [[ "$RETIRE_MOUNT_ID" =~ ^[0-9]+$ ]] ||
    die 'Invalid archive mount ID.'
}

verify_retirement_mount() {
  local target source mount_id parent_name serial model live_id

  target="$(findmnt -rn -o TARGET --mountpoint "$MOUNT")" ||
    die 'Archive mount is no longer available.'

  source="$(findmnt -rn -o SOURCE --mountpoint "$MOUNT")" ||
    die 'Archive mount source is unavailable.'

  mount_id="$(findmnt -rn -o ID --mountpoint "$MOUNT")" ||
    die 'Archive mount ID is unavailable.'

  [[ "$target" == "$MOUNT" &&
     "$mount_id" == "$RETIRE_MOUNT_ID" &&
     "$source" == "$SOURCE" &&
     -b "$source" ]] ||
    die 'Archive mount identity changed. Retirement stopped.'

  parent_name="$(
    lsblk -dn -o PKNAME "$source" | xargs
  )" || die 'Unable to resolve archive physical disk.'

  [[ -n "$parent_name" &&
     "$parent_name" == "$PARENT_NAME" &&
     "/dev/$parent_name" == "$PARENT" ]] ||
    die 'Archive parent disk changed. Retirement stopped.'

  serial="$(
    lsblk -dn -o SERIAL "$PARENT" | xargs
  )" || die 'Unable to read archive disk serial.'

  model="$(
    lsblk -dn -o MODEL "$PARENT" | xargs
  )" || die 'Unable to read archive disk model.'

  live_id="${model// /_}_${serial}"

  [[ -n "$serial" && -n "$model" &&
     "$serial" == "$SERIAL" &&
     "$model" == "$MODEL" &&
     "$live_id" == "$ID" &&
     "$(basename "$MOUNT")" == "$ID" ]] ||
    die 'Archive hardware identity changed. Retirement stopped.'

  [[ -f "$META" && ! -L "$META" ]] ||
    die 'Registered device metadata became unsafe.'

  grep -Fq "\"serial\": \"$SERIAL\"" "$META" ||
    die 'Registered device serial changed.'

  grep -Fq "\"device_id\": \"$ID\"" "$META" ||
    die 'Registered drive identifier changed.'
}

if [[ "$MODE" == retire ]]; then
  [[ -n "${COLD_EXPECTED_DEVICE_ID:-}" &&
     "$COLD_EXPECTED_DEVICE_ID" == "$ID" ]] ||
    die 'Retirement expected drive identity is absent or different.'

  # The existing hardware checks and integrity lock apply here.
  init_retirement_mount
  verify_retirement_mount
  [[ ! -L "$DIR" && ! -L "$DIR/manifests" &&
     ! -L "$DIR/snapshots" && ! -L "$MANIFEST" ]] ||
    die 'Unsafe integrity record path.'

  declare -A RETIRE=()

  for path in "${!KNOWN[@]}"; do
    FILE="$MOUNT/${path#./}"

    if [[ -L "$FILE" ]]; then
      die "Registered path became a symbolic link: $path"
    elif [[ -e "$FILE" ]]; then
      [[ -f "$FILE" ]] ||
        die "Registered path is not a regular file: $path"
    else
      RETIRE["$path"]="${KNOWN[$path]}"
    fi
  done

  COUNT="${#RETIRE[@]}"
  printf '\nMissing registered files: %s\n' "$COUNT"

  if (( COUNT == 0 )); then
    echo 'No registered files need retirement.'
    COMPLETED=1
    exit 0
  fi

  mapfile -t SORTED < <(
    printf '%s\n' "${!RETIRE[@]}" | LC_ALL=C sort
  )

  for path in "${SORTED[@]}"; do
    printf 'MISSING  %s  %s\n' \
      "${RETIRE[$path]}" "$path"
  done

  echo
  echo 'Only the listed SHA-256 registrations will be retired.'
  echo 'No physical archive files will be changed.'
  echo 'The previous manifest will be preserved.'

  read -r -p \
    "Type RETIRE $COUNT $ID to approve ALL listed entries: " \
    CONFIRM

  if [[ "$CONFIRM" != "RETIRE $COUNT $ID" ]]; then
    echo 'Cancelled; no changes made.'
    COMPLETED=1
    exit 0
  fi

  # Reject a replaced or remounted drive before rescanning.
  verify_retirement_mount

  # Recheck the complete inventory after confirmation.
  RESCAN="$(mktemp "$DIR/manifests/.rescan.XXXXXXXX")"

  (
    cd "$MOUNT"
    find . -type f -print0 | LC_ALL=C sort -z > "$RESCAN"
  )

  if ! cmp -s \
    <(LC_ALL=C sort -z "$ALL_LIST") "$RESCAN"; then
    die 'Physical inventory changed during approval.'
  fi

  rm -f -- "$RESCAN"
  RESCAN=''

  for path in "${SORTED[@]}"; do
    FILE="$MOUNT/${path#./}"
    [[ ! -e "$FILE" && ! -L "$FILE" ]] ||
      die "Registered file reappeared: $path"
  done

  # Preserve every manifest entry not explicitly retired.
  BEFORE="$(sha256sum -- "$MANIFEST" | cut -d ' ' -f 1)"
  STAGED="$(mktemp "$DIR/manifests/.retire.XXXXXXXX")"

  while IFS= read -r line || [[ -n "$line" ]]; do
    path="${line:66}"
    if [[ ! -v RETIRE["$path"] ]]; then
      printf '%s\n' "$line" >> "$STAGED"
    fi
  done < "$MANIFEST"

  chmod 644 -- "$STAGED"
  AFTER="$(sha256sum -- "$STAGED" | cut -d ' ' -f 1)"

  [[ "$BEFORE" != "$AFTER" ]] ||
    die 'Manifest unchanged; refusing to publish.'

  mkdir -p -- "$DIR/retirements"

  [[ ! -L "$DIR/retirements" &&
     -d "$DIR/retirements" ]] ||
    die 'Unsafe retirement audit directory.'

  LABEL="$(date -u +%Y%m%dT%H%M%SZ)_${BASHPID}"
  SNAP_NAME="baseline_retirement_${LABEL}.sha256"
  SNAP="$DIR/snapshots/$SNAP_NAME"
  RECEIPT="$DIR/retirements/retirement_${LABEL}.tsv"

  [[ ! -e "$SNAP" && ! -L "$SNAP" &&
     ! -e "$RECEIPT" && ! -L "$RECEIPT" ]] ||
    die 'Retirement evidence already exists.'

  RECEIPT_TMP="$(mktemp "$DIR/retirements/.receipt.XXXXXXXX")"

  {
    printf 'COLD_SHA_RETIRE_V1\n'
    printf 'drive\t%s\n' "$ID"
    printf 'before\t%s\n' "$BEFORE"
    printf 'after\t%s\n' "$AFTER"
    printf 'snapshot\t%s\n' "$SNAP_NAME"

    for path in "${SORTED[@]}"; do
      printf 'retired\t%s\t%s\n' \
        "${RETIRE[$path]}" "$path"
    done
  } > "$RECEIPT_TMP"

  chmod 644 -- "$RECEIPT_TMP"

  # Preserve the complete original manifest.
  cp -p -- "$MANIFEST" "$SNAP" ||
    die 'Historical manifest snapshot failed.'

  chmod 644 -- "$SNAP"

  [[ "$(sha256sum -- "$SNAP" | cut -d ' ' -f 1)" == "$BEFORE" ]] ||
    die 'Historical snapshot digest mismatch.'

  [[ "$(sha256sum -- "$MANIFEST" | cut -d ' ' -f 1)" == "$BEFORE" ]] ||
    die 'Active manifest changed during preparation.'

  # Publish evidence first. An interrupted publication must
  # never provide silently accepted retirement evidence.
  sync -f -- "$SNAP" "$RECEIPT_TMP" "$STAGED" ||
    die 'Could not flush retirement evidence.'

  mv -T -- "$RECEIPT_TMP" "$RECEIPT"
  RECEIPT_TMP=''

  sync -f -- "$RECEIPT" ||
    die 'Could not flush retirement receipt.'

  # Check physical identity again immediately before
  # committing the manifest replacement.
  verify_retirement_mount

  # Reject concurrent or unexpected manifest changes
  # after publication of the retirement evidence.
  [[ -f "$MANIFEST" && ! -L "$MANIFEST" ]] ||
    die 'Active manifest became unsafe before retirement publication.'

  [[ "$(sha256sum -- "$MANIFEST" | cut -d ' ' -f 1)" == "$BEFORE" ]] ||
    die 'Active manifest changed before retirement publication.'

  # Atomic replacement on the same filesystem.
  mv -T -- "$STAGED" "$MANIFEST"
  STAGED=''

  sync -f -- "$MANIFEST" ||
    die 'Could not flush active manifest.'

  COMPLETED=1

  printf '\nRETIRED: %s registered entries.\n' "$COUNT"
  printf 'Snapshot: %s\n' "$SNAP"
  printf 'Receipt: %s\n' "$RECEIPT"

  echo 'Catalog synchronization is still required.'
  echo 'Run a full checksum verification separately.'
  exit 0
fi

if [[ "$MODE" == register ]]; then
  NEW_COUNT=0
  while IFS= read -r -d '' path; do ((NEW_COUNT+=1)); done < "$NEW_LIST"
  printf 'New, unregistered files: %d\n' "$NEW_COUNT"
  if (( NEW_COUNT == 0 )); then echo 'Nothing to register.'; record_run register NO_CHANGES "${#KNOWN[@]}" 0 0; COMPLETED=1; exit 0; fi
  echo 'These files will be trusted AS THEY CURRENTLY EXIST ON THIS DISK.'
  echo 'This does not compare them with source files. Existing checksums are preserved.'
  read -r -p 'Type REGISTER to hash and add these files: ' CONFIRM
  [[ "$CONFIRM" == 'REGISTER' ]] || { echo 'Cancelled; no changes made.'; COMPLETED=1; exit 0; }
  STAGED="$(mktemp "$DIR/manifests/.staged.XXXXXXXX")"
  cp -- "$MANIFEST" "$STAGED"
  DONE=0
  while IFS= read -r -d '' path; do
    FILE="$MOUNT/${path#./}"
    [[ -f "$FILE" && ! -L "$FILE" ]] || die "File disappeared: $path"
    BEFORE="$(stat -c '%s:%Y:%y' -- "$FILE")" || die "Cannot stat: $path"
    HASH="$(sha256sum -- "$FILE")" || die "Cannot hash: $path"
    HASH="${HASH:0:64}"
    AFTER="$(stat -c '%s:%Y:%y' -- "$FILE")" || die "Cannot stat after hashing: $path"
    [[ "$BEFORE" == "$AFTER" ]] || die "File changed while hashing: $path"
    printf '%s  %s\n' "$HASH" "$path" >> "$STAGED"
    ((DONE+=1))
    printf '\rHashed %d/%d new files' "$DONE" "$NEW_COUNT"
  done < "$NEW_LIST"
  echo
  # Snapshot previous manifest, then atomically publish a completed new version.
  SNAP="$DIR/snapshots/baseline_$(date -u +%Y%m%dT%H%M%SZ)_$$.sha256"
  cp -p -- "$MANIFEST" "$SNAP" || die 'Could not preserve previous manifest.'
  chmod 644 -- "$SNAP" || die 'Could not set snapshot read permissions.'
  # mktemp creates mode 600; explicitly make the published manifest readable.
  chmod 644 -- "$STAGED" || die 'Could not set manifest read permissions.'
  mv -f -- "$STAGED" "$MANIFEST"
  STAGED=''
  record_run register PASS "$((${#KNOWN[@]}+DONE))" "$DONE" 0
  COMPLETED=1
  printf 'REGISTERED: %d new files. Previous manifest snapshot: %s\n' "$DONE" "$SNAP"
  echo 'Run verify separately whenever you are ready.'
  exit 0
fi
# Full verification includes untracked-file detection, missing files and
# rehashing every tracked file; it never modifies the archive or its baseline.
PROBLEMS=0
UNTRACKED=0
CHECKED=0
while IFS= read -r -d '' path; do
  if [[ ! -v KNOWN["$path"] ]]; then issue UNREGISTERED "$path"; ((PROBLEMS+=1)); ((UNTRACKED+=1)); fi
done < "$ALL_LIST"
for path in "${!KNOWN[@]}"; do
  FILE="$MOUNT/${path#./}"
  if [[ ! -f "$FILE" || -L "$FILE" ]]; then issue MISSING "$path"; ((PROBLEMS+=1)); continue; fi
  if ! ACTUAL="$(sha256sum -- "$FILE")"; then issue READ_ERROR "$path"; ((PROBLEMS+=1)); continue; fi
  ACTUAL="${ACTUAL:0:64}"
  if [[ "$ACTUAL" != "${KNOWN[$path]}" ]]; then issue HASH_MISMATCH "$path"; ((PROBLEMS+=1)); fi
  ((CHECKED+=1))
done
if (( PROBLEMS == 0 )); then RESULT=PASS; else RESULT=FAIL; fi
record_run verify "$RESULT" "${#KNOWN[@]}" "$UNTRACKED" "$PROBLEMS"
COMPLETED=1
printf '\nVERIFY RESULT: %s | checked: %d | tracked: %d | unregistered: %d | issues: %d\n' "$RESULT" "$CHECKED" "${#KNOWN[@]}" "$UNTRACKED" "$PROBLEMS"
printf 'Logs: %s\n' "$DIR/verification_logs"
[[ "$RESULT" == PASS ]]
