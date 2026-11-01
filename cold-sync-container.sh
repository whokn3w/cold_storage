#!/usr/bin/env bash
set -euo pipefail

(( $# == 2 )) || {
  echo "Usage: launcher history|catalog DRIVE_ID" >&2
  exit 64
}

mode="$1"
drive="$2"

[[ "$drive" =~ ^[A-Za-z0-9._-]{1,256}$ ]] || {
  echo "STOP: Invalid drive ID." >&2
  exit 65
}

case "$mode" in
  history) script="/app/history_sync_cli.py" ;;
  catalog) script="/app/catalog_refresh_cli.py" ;;
  *) echo "STOP: Invalid mode." >&2; exit 64 ;;
esac

root="${COLD_TEST_ROOT:-}"
container="${COLD_SYNC_CONTAINER:-}"

[[ "$root" =~ ^/tmp/cold-storage-step352\.[A-Za-z0-9]{8}$ &&
   -d "$root" && ! -L "$root" ]] || {
  echo "STOP: Invalid isolated test directory." >&2
  exit 65
}

[[ "$container" == "cold_storage_v070_test_${root##*.}" ]] || {
  echo "STOP: Invalid test container identity." >&2
  exit 65
}

metadata="$(
  docker inspect --type container \
    --format '{{.Config.Image}}|{{.State.Running}}|{{index .Config.Labels "pucksly.cold-storage.test-only"}}|{{.HostConfig.NetworkMode}}' \
    "$container" 2>/dev/null
)" || exit 65

[[ "$metadata" == "cold_storage:0.7.0-dev-step348|true|v0.7.0|none" ]] || {
  echo "STOP: Unexpected container configuration." >&2
  exit 65
}

mounts="$(
  docker inspect --type container \
    --format '{{range .Mounts}}{{printf "%s=%s:%t\n" .Destination .Source .RW}}{{end}}' \
    "$container" |
    sed '/^[[:space:]]*$/d' |
    sort
)"

expected="$(
  printf '%s\n' \
    "/config=$root/config:true" \
    "/records/devices=$root/devices:false" |
    sort
)"

[[ "$mounts" == "$expected" ]] || {
  echo "STOP: Unexpected container mounts." >&2
  exit 65
}

exec docker exec "$container" python "$script" "$drive"
