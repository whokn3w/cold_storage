#!/usr/bin/env bash
# Register a new drive for catalog-first use. Archive filesystem is read-only.
set -Eeuo pipefail
umask 022
BASE='/mnt/user/Backups/cold_storage'
ROOT='/mnt/disks'
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ $# -eq 0 ]] || die 'Usage: bash cold-add-drive.sh'
for tool in findmnt lsblk flock mktemp; do
  command -v "$tool" >/dev/null || die "Required tool unavailable: $tool"
done
mapfile -t MOUNTS < <(findmnt -rn -o TARGET | grep "^${ROOT}/" || true)
[[ ${#MOUNTS[@]} -eq 1 ]] || die 'Mount exactly one Unassigned Devices disk under /mnt/disks.'
MOUNT="${MOUNTS[0]}"
[[ "$(dirname "$MOUNT")" == "$ROOT" && ! -L "$MOUNT" ]] || die 'Unexpected mount location.'
SOURCE="$(findmnt -rn -o SOURCE --mountpoint "$MOUNT")"
[[ -b "$SOURCE" ]] || die 'Mount is not backed by a block device.'
[[ "$(lsblk -dn -o TYPE "$SOURCE" | xargs)" == part ]] || die 'Expected a disk partition.'
PARENT_NAME="$(lsblk -dn -o PKNAME "$SOURCE" | xargs)"
[[ -n "$PARENT_NAME" ]] || die 'Cannot identify parent disk.'
PARENT="/dev/$PARENT_NAME"
[[ "$(lsblk -dn -o TYPE "$PARENT" | xargs)" == disk ]] || die 'Unexpected parent device.'
SERIAL="$(lsblk -dn -o SERIAL "$PARENT" | xargs)"
MODEL="$(lsblk -dn -o MODEL "$PARENT" | xargs)"
SIZE="$(lsblk -bdn -o SIZE "$PARENT" | xargs)"
[[ -n "$SERIAL" && -n "$MODEL" && "$SIZE" =~ ^[0-9]+$ ]] || die 'Missing hardware identity or capacity.'
ID="${MODEL// /_}_${SERIAL}"
[[ "$ID" =~ ^[A-Za-z0-9._-]+$ ]] || die 'Unexpected characters in identifier.'
[[ "$(basename "$MOUNT")" == "$ID" ]] || die "Mount name mismatch. Expected: $ID"
DIR="$BASE/devices/$ID"
[[ ! -e "$DIR" && ! -L "$DIR" ]] || die 'Drive records already exist; nothing changed. Use Refresh catalog for a registered drive.'
printf '\nDevice: %s\nSerial: %s\nSource: %s\nMount: %s\nSize: %s bytes\n\n' "$ID" "$SERIAL" "$SOURCE" "$MOUNT" "$SIZE"
echo 'This creates drive records only. It does not hash or modify archive files.'
read -r -p 'Register this disk for cold storage? [yes/no]: ' ANSWER
[[ "$ANSWER" == yes ]] || { echo 'Registration cancelled.'; exit 0; }
# Recheck the mount and hardware after the interactive confirmation.
[[ "$(findmnt -rn -o SOURCE --mountpoint "$MOUNT")" == "$SOURCE" ]] || die 'Mount changed during confirmation.'
[[ "$(lsblk -dn -o PKNAME "$SOURCE" | xargs)" == "$PARENT_NAME" &&
   "$(lsblk -dn -o SERIAL "$PARENT" | xargs)" == "$SERIAL" &&
   "$(lsblk -dn -o MODEL "$PARENT" | xargs)" == "$MODEL" ]] || die 'Disk identity changed during confirmation.'
mkdir -p "$BASE/devices"
exec 9>"$BASE/.drive-setup.lock"
flock -n 9 || die 'Another drive setup is running.'
[[ ! -e "$DIR" && ! -L "$DIR" ]] || die 'Drive records now exist; nothing overwritten.'
# Stage outside devices so refresh cannot see incomplete registration metadata.
STAGED="$(mktemp -d "$BASE/.drive-setup.XXXXXXXX")"
cleanup() { [[ -z "$STAGED" ]] || rm -rf -- "$STAGED"; }
trap cleanup EXIT
mkdir "$STAGED/manifests" "$STAGED/verification_logs" "$STAGED/snapshots"
cat > "$STAGED/device.json" <<EOF
{
  "device_id": "$ID",
  "model": "$MODEL",
  "serial": "$SERIAL",
  "capacity_bytes": $SIZE,
  "registered_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "verification_interval_days": 180,
  "last_successful_verification": null,
  "baseline_created": false
}
EOF
: > "$STAGED/manifests/baseline.sha256"
chmod 755 "$STAGED"
# -T prevents nesting; -n prevents replacement if a destination appeared.
mv -T -n -- "$STAGED" "$DIR"
[[ ! -e "$STAGED" ]] || die 'Destination appeared; existing records preserved.'
STAGED=''
printf '\nSUCCESS: Registered %s\nRecords: %s\n' "$ID" "$DIR"
echo 'Next: select Refresh catalog on the homepage. Checksums are not required.'
echo 'Later, optionally run cold-register-sync; verify separately with cold-verify-sync.'
