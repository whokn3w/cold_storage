
"""Read-only physical archive inventory.

The caller must first verify the mounted drive's hardware identity.
This module does not read file contents or calculate checksums.
"""

import os
import stat
from pathlib import Path


def _validate_name(name):
    if not name or name in (".", ".."):
        raise ValueError("Invalid archive path component")

    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ValueError(
            "Archive filename contains unsupported control characters"
        )

    name.encode("utf-8", errors="strict")


def scan_files(root):
    """Return sorted relative paths of regular files."""

    root = Path(root)
    initial = os.stat(root, follow_symlinks=False)

    if not stat.S_ISDIR(initial.st_mode):
        raise ValueError("Archive root is not a real directory")

    device = initial.st_dev
    discovered = []
    directories = [(root, ())]

    while directories:
        directory, components = directories.pop()

        with os.scandir(directory) as iterator:
            entries = list(iterator)

        for entry in entries:
            _validate_name(entry.name)

            metadata = entry.stat(follow_symlinks=False)

            if metadata.st_dev != device:
                raise ValueError(
                    "Unexpected filesystem boundary: " + entry.path
                )

            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError(
                    "Symbolic link in archive: " + entry.path
                )

            parts = components + (entry.name,)
            relative = "/".join(parts)

            if stat.S_ISDIR(metadata.st_mode):
                directories.append((Path(entry.path), parts))

            elif stat.S_ISREG(metadata.st_mode):
                discovered.append(relative)

            else:
                raise ValueError(
                    "Unsupported archive file type: " + entry.path
                )

    final = os.stat(root, follow_symlinks=False)

    if (
        final.st_dev != initial.st_dev
        or final.st_ino != initial.st_ino
        or not stat.S_ISDIR(final.st_mode)
    ):
        raise RuntimeError(
            "Archive mount changed during inventory"
        )

    discovered.sort()
    return discovered
