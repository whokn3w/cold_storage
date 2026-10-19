# Cold Storage

Cold Storage is a self-hosted web application for cataloging and browsing files stored on offline hard drives.

It maintains a searchable SQLite catalog, allowing archived files to be located without reconnecting their physical drives.

## Features

- Browse files by individual archive drive
- Search cataloged files
- Combined Master Index across multiple drives
- Display duplicate filenames with their associated drives
- Track registration and verification history
- Identify files registered since the last successful full verification
- Track verification due dates
- Create SQLite catalog backups

## How It Works

Cold Storage imports existing archive metadata, manifests, and verification logs into a persistent SQLite database.

The application does not copy archived files or perform disk integrity checks. Registration and verification are handled separately.

Refreshing the catalog does not verify archived files.

## Installation

Docker Compose is recommended.

1. Clone or download this repository.
2. Create the required directories:

   mkdir -p data/config data/records/devices data/backups

3. Place compatible archive metadata under `data/records/devices`.
4. Start the application:

   docker compose up -d

5. Open http://localhost:8787

The included Compose configuration uses:

- `/config` for the SQLite catalog
- `/records` for read-only archive metadata
- `/backups` for SQLite database backups

## Docker Image

ghcr.io/whokn3w/cold_storage:0.4.2

## Configuration

| Variable | Description |
|---|---|
| DB_PATH | SQLite catalog location |
| DEVICES_PATH | Archive metadata directory |
| BACKUPS_PATH | SQLite backup destination |
| TZ | Timezone for displayed timestamps and due dates |

## Security

Cold Storage does not currently provide authentication.

Use it only on a trusted local network or behind an appropriately secured access layer.

Do not expose its web interface directly to the public internet.

Catalog databases, archive records, and backups must remain outside the Docker image.

## Data Preservation

Keep the SQLite database, archive metadata, and backup directories when upgrading.

Never delete these directories during a container upgrade.

## Version

v0.4.2

## v0.5.0 development: storage snapshot safeguards

Refresh Catalog attempts a low-impact `statvfs` measurement only when the
registered model/serial, mounted filesystem, kernel major:minor device identity,
and a unique matching `ata-...-partN` persistent hardware identifier agree.
The current `/dev/sdX` partition name is discovered at refresh time, never
persisted as an identity. A disconnected or mismatched disk retains its last
snapshot. This feature requires read-only `/mnt/disks` and `/dev/disk/by-id`
mounts and access to `/sys/dev/block` inside the container. No raw block devices
are opened, no file contents are scanned, and no disks are mounted automatically.
Test this in an isolated container/database before using in production.
