#!/usr/bin/env bash
# Cold Storage production synchronization launcher (interface v1).
# Requires the exact approved application image and mounts.
# Does not replace the original integrity engine.
set -euo pipefail

if (( $# != 2 )); then
  echo "Usage: cold-sync-production.sh history|catalog DRIVE_ID" >&2
  exit 64
fi

mode="$1"
drive="$2"

case "$mode" in
  history|catalog) ;;
  *)
    echo "STOP: Invalid synchronization mode." >&2
    exit 64
    ;;
esac

if [[ ! "$drive" =~ ^[A-Za-z0-9._-]{1,256}$ ]]; then
  echo "STOP: Invalid drive identifier." >&2
  exit 65
fi

container="cold_storage"
image="ghcr.io/whokn3w/cold_storage:latest"

# Discover the installed version without scanning archive disks.
# Version 0.7.1 is the sole supported legacy exception.
release_version="$(
  docker exec "$container" python -c '
import app
import re

version = getattr(app, "APP_VERSION", None)

if (
    not isinstance(version, str)
    or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
):
    raise SystemExit(1)

interface = getattr(app, "SYNC_API_VERSION", None)

if interface is None:
    if version != "0.7.1":
        raise SystemExit(1)
elif type(interface) is not int or interface != 1:
    raise SystemExit(1)

print(version)
'
)" || {
  echo "STOP: Unsupported application version or sync interface." >&2
  exit 65
}

# Require the locally installed versioned release to match
# both the latest image and the running production container.
release_image="ghcr.io/whokn3w/cold_storage:${release_version}"
approved_image_id="$(
  docker image inspect "$release_image" --format '{{.Id}}' 2>/dev/null
)" || {
  echo "STOP: Approved versioned release image unavailable." >&2
  exit 65
}
if [[ ! "$approved_image_id" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "STOP: Invalid approved release image identity." >&2
  exit 65
fi

appdata="/mnt/user/appdata/cold_storage"
records="/mnt/user/Backups/cold_storage"

image_id="$(
  docker image inspect "$image" \
    --format '{{.Id}}' 2>/dev/null
)" || {
  echo "STOP: Approved image unavailable." >&2
  exit 65
}

if [[ "$image_id" != "$approved_image_id" ]]; then
  echo "STOP: Release image identity mismatch." >&2
  exit 65
fi

container_id="$(
  docker inspect --type container "$container" \
    --format '{{.Id}}' 2>/dev/null
)" || {
  echo "STOP: Production application container unavailable." >&2
  exit 65
}

identity="$(
  docker inspect --type container "$container_id" \
    --format '{{.Name}}|{{.Config.Image}}|{{.Image}}|{{.State.Running}}|{{.Config.User}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}'
)" || exit 65

expected_identity="/cold_storage|${image}|${approved_image_id}|true|1000:1000|bridge|false"

if [[ "$identity" != "$expected_identity" ]]; then
  echo "STOP: Production container identity or configuration mismatch." >&2
  exit 65
fi

mounts="$(
  docker inspect --type container "$container_id" \
    --format '{{range .Mounts}}{{printf "%s=%s:%t\n" .Destination .Source .RW}}{{end}}' |
    sed '/^[[:space:]]*$/d' |
    sort
)" || exit 65

expected_mounts="$(
  printf '%s\n' \
    "/archive-mounts=/mnt/disks:false" \
    "/backups=/mnt/user/Backups/cold_storage/catalog/backups:true" \
    "/config=/mnt/user/appdata/cold_storage:true" \
    "/host-disk-by-id=/dev/disk/by-id:false" \
    "/host-sys-dev-block=/sys/dev/block:false" \
    "/records=/mnt/user/Backups/cold_storage:false" |
    sort
)"

if [[ "$mounts" != "$expected_mounts" ]]; then
  echo "STOP: Production container mounts do not match the approved layout." >&2
  exit 65
fi

if [[ ! -d "$appdata" || -L "$appdata" ||
      ! -f "$appdata/cold_storage.db" ||
      -L "$appdata/cold_storage.db" ||
      ! -d "$records/devices" ||
      -L "$records/devices" ]]; then
  echo "STOP: Production catalog or records directory is unsafe." >&2
  exit 65
fi

# Verify application runtime paths without initializing or scanning.
docker exec "$container_id" python -c '
import app
from pathlib import Path
assert (
    getattr(app, "SYNC_API_VERSION", None) == 1
    or (
        app.APP_VERSION == "0.7.1"
        and not hasattr(app, "SYNC_API_VERSION")
    )
)
assert Path("/app/history_sync_cli.py").is_file()
assert Path("/app/catalog_refresh_cli.py").is_file()
assert app.DB == "/config/cold_storage.db"
assert Path(app.DEVICES) == Path("/records/devices")
assert Path(app.ARCHIVE_MOUNTS) == Path("/archive-mounts")
' || {
  echo "STOP: Application runtime configuration mismatch." >&2
  exit 65
}

if [[ "$mode" == history ]]; then
  # No archive mounts, hardware paths, or network.
  exec docker run --rm \
    --network none \
    --read-only \
    --user 1000:1000 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --tmpfs /tmp:rw,nosuid,nodev,size=16m \
    -v "$appdata:/config:rw" \
    -v "$records/devices:/records/devices:ro" \
    --entrypoint python \
    "$approved_image_id" \
    /app/history_sync_cli.py "$drive"
fi

# Catalog refresh needs hardware identity verification.
# The Python CLI targets exactly the selected drive.
# Catalog mode runs in a new container so drives mounted after
# the dashboard started are visible. Archive mounts remain
# recursively read-only. No Docker socket or raw devices exposed.
exec docker run --rm \
  --network none \
  --read-only \
  --user 1000:1000 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=16m \
  --mount "type=bind,source=$appdata,target=/config" \
  --mount "type=bind,source=$records,target=/records,readonly" \
  --mount type=bind,source=/mnt/disks,target=/archive-mounts,readonly,bind-propagation=rprivate,bind-recursive=readonly \
  --mount type=bind,source=/dev/disk/by-id,target=/host-disk-by-id,readonly \
  --mount type=bind,source=/sys/dev/block,target=/host-sys-dev-block,readonly \
  --entrypoint python \
  "$approved_image_id" \
  /app/catalog_refresh_cli.py "$drive"
