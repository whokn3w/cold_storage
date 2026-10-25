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
- View archive drive capacity and recorded storage snapshots
- Display SHA-256 checksum registration and verification status
- Display optional PAR2 recovery coverage and verification history
- View terminal commands in a dedicated Commands tab
- Preserve registered drive information when a checksum manifest is not yet available

## How It Works

Cold Storage imports existing archive metadata, manifests, and verification logs into a persistent SQLite database.

The application does not copy archived files or automatically perform disk integrity checks. SHA-256 registration, SHA-256 verification, and PAR2 operations are handled separately through host-side tools.

The dashboard displays the results recorded by those tools. A historical successful verification does not guarantee the current contents of a disconnected disk.

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

ghcr.io/whokn3w/cold_storage:0.6.0

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

v0.6.0

## Storage Snapshot Safeguards

Refresh Catalog attempts a low-impact `statvfs` measurement only when the
registered model/serial, mounted filesystem, kernel major:minor device identity,
and a unique matching `ata-...-partN` persistent hardware identifier agree.
The current `/dev/sdX` partition name is discovered at refresh time, never
persisted as an identity. A disconnected or mismatched disk retains its last
snapshot. This feature requires read-only `/mnt/disks` and `/dev/disk/by-id`
mounts and access to `/sys/dev/block` inside the container. No raw block devices
are opened, no file contents are scanned, and no disks are mounted automatically.
Test this in an isolated container/database before using in production.

## Version 0.6.0 Dashboard

The Overview displays registered archive drives, manufacturer information,
model and serial identifiers, capacity, recorded storage usage, and
verification-related attention messages.

The navigation includes:

- Overview
- Archive Drives
- Master Index
- Verification History
- Commands

The Commands page displays terminal commands for SHA-256 registration,
SHA-256 verification, PAR2 management, supplemental PAR2 creation,
and PAR2 recovery-set verification.

Commands shown in the web interface are informational. Displaying a
command does not execute it.

### SHA-256 Status

SHA-256 status comes from imported registration and verification records.

A drive can be registered in the catalog before a checksum manifest exists.
Such a drive may show NOT INITIALIZED and NOT SCHEDULED.

INCOMPLETE or VERIFY NEEDED indicates that recorded verification coverage
is not complete or current. It does not, by itself, establish corruption.

Refresh Catalog updates the database using available metadata.
It does not read archived file contents or calculate file checksums.

### Optional PAR2 Recovery

PAR2 coverage is optional and can be selected for particular archive
folders. The dashboard reads PAR2 selections and verification receipts
from persistent configuration.

PAR2 VERIFIED describes the recorded verification result. It is not
a guarantee that every file remains recoverable indefinitely.

PAR2 verification is performed separately using the host launcher:

    bash /boot/custom/cold-storage/par2-verify.sh plan DRIVE_ID
    bash /boot/custom/cold-storage/par2-verify.sh verify DRIVE_ID

These commands require a separately installed, compatible host launcher,
the PAR2 utility container, and the appropriate recovery files.

The dashboard image does not install or execute those host scripts.
Do not assume a displayed command is available until its host-side
script has been installed and tested.

Preserve the following persistent configuration files where applicable:

- /config/par2-selections.json
- /config/par2-verification-history.jsonl

### Optional unRAID Storage Snapshot Mounts

The included Docker Compose file is portable and does not automatically
mount host disks or hardware identity paths.

On a compatible unRAID host, recorded storage snapshots can use these
additional read-only mounts:

    - /mnt/disks:/archive-mounts:ro,rprivate
    - /dev/disk/by-id:/host-disk-by-id:ro
    - /sys/dev/block:/host-sys-dev-block:ro

Add these under the service's volumes section only when the corresponding
host paths exist and their use is appropriate.

The application must match the registered drive model and serial, mounted
filesystem, kernel device identity, and a unique persistent hardware ID
before recording a new storage snapshot.

These mounts do not grant permission to write archived files. Missing,
disconnected, or mismatched drives retain their previous recorded snapshot.

### unRAID Docker Manager Integration

On unRAID, manage the production container through the built-in Docker
Manager and its saved container template.

The production installation uses:

- Container name: `cold_storage`
- Saved template: `my-cold_storage.xml`
- Management label: `net.unraid.docker.managed=dockerman`
- WebUI port: `8787`

Preserve the saved template, Docker Manager integration, and existing
container settings when upgrading. Creating a replacement container
outside Docker Manager may cause unRAID to display it as "3rd Party".

For future update detection, the recommended repository reference is:

    ghcr.io/whokn3w/cold_storage:latest

The GitHub publishing workflow also publishes version-specific tags,
such as `0.6.0`, which can be used for controlled rollbacks.

Using a fixed version tag does not automatically track newer version
tags. The `latest` reference allows Docker Manager to check for newer
published images; applying updates remains a separate action.

Before changing the production template, preserve a copy of
`my-cold_storage.xml`, the SQLite catalog, and the PAR2 configuration.

Changes to the repository's `compose.yaml` do not modify the saved
unRAID Docker Manager template.

### Upgrading

Before replacing an existing container:

1. Preserve the current container configuration and image tag.
2. Create and validate a backup of the persistent SQLite database.
3. Preserve existing PAR2 selections and verification history.
4. Verify the new image with a separate test container and database.
5. Confirm the new container uses the correct persistent mounts.
6. Verify the dashboard and recorded statuses before retiring the old image.

Do not delete the original database, archive records, backup directories,
or PAR2 configuration during an upgrade.

A Docker image upgrade does not automatically install unRAID host scripts.
