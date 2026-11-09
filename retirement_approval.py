"""Validate host-approved SHA-256 retirements. Read-only."""
import hashlib
import re


def _regular_bytes(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Expected regular file: {path.name}")
    return path.read_bytes()


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def authorized_retirements(
    folder, drive_id, saved_hashes, physical_paths,
    parse_manifest
):
    pending = {
        path: checksum
        for path, checksum in saved_hashes.items()
        if checksum is not None and path not in physical_paths
    }
    if not pending:
        return set()

    receipts = folder / "retirements"
    snapshots = folder / "snapshots"
    manifest = folder / "manifests" / "baseline.sha256"

    if (
        receipts.is_symlink() or not receipts.is_dir()
        or snapshots.is_symlink() or not snapshots.is_dir()
    ):
        raise ValueError("Missing or unsafe retirement evidence")

    active_bytes = _regular_bytes(manifest)
    active = dict(parse_manifest(manifest))

    if any(
        not re.fullmatch(r"[0-9a-f]{64}", h)
        for h in pending.values()
    ):
        raise ValueError("Invalid saved checksum")

    matches = []

    for receipt in sorted(receipts.glob("retirement_*.tsv")):
        raw = _regular_bytes(receipt)

        if len(raw) > 4 * 1024 * 1024 or not raw.endswith(b"\n"):
            raise ValueError("Invalid retirement receipt")

        try:
            fields = [
                line.split("\t")
                for line in raw.decode("utf-8").splitlines()
            ]
        except UnicodeError as exc:
            raise ValueError("Invalid receipt encoding") from exc

        if (
            len(fields) < 6
            or fields[0] != ["COLD_SHA_RETIRE_V1"]
            or len(fields[1]) != 2 or fields[1][0] != "drive"
            or len(fields[2]) != 2 or fields[2][0] != "before"
            or len(fields[3]) != 2 or fields[3][0] != "after"
            or len(fields[4]) != 2 or fields[4][0] != "snapshot"
        ):
            raise ValueError("Malformed retirement receipt")

        if fields[1][1] != drive_id:
            continue

        before, after, snapshot_name = (
            fields[2][1], fields[3][1], fields[4][1]
        )

        if not all(
            re.fullmatch(r"[0-9a-f]{64}", value)
            for value in (before, after)
        ):
            raise ValueError("Invalid manifest digest")

        if not re.fullmatch(
            r"baseline_retirement_[0-9]{8}T[0-9]{6}Z_[0-9]+\.sha256",
            snapshot_name
        ):
            raise ValueError("Unsafe snapshot name")

        original_path = snapshots / snapshot_name
        original_bytes = _regular_bytes(original_path)

        if _sha(original_bytes) != before:
            raise ValueError("Historical manifest altered")

        original = dict(parse_manifest(original_path))
        retired = {}

        for entry in fields[5:]:
            if len(entry) != 3 or entry[0] != "retired":
                raise ValueError("Malformed retired-file entry")

            checksum, path = entry[1], entry[2]

            if (
                not re.fullmatch(r"[0-9a-f]{64}", checksum)
                or not path.startswith("./")
                or any(
                    part in ("", ".", "..")
                    for part in path[2:].split("/")
                )
                or any(c in path for c in ("\\", "\r", "\n", "\t"))
                or path[2:] in retired
            ):
                raise ValueError("Unsafe or duplicate retired file")

            retired[path[2:]] = checksum

        if not retired:
            raise ValueError("Empty retirement approval")

        # Historical receipts are not automatically approvals
        # for the current missing-file set.
        if retired != pending:
            continue

        if any(
            original.get(path) != checksum
            for path, checksum in retired.items()
        ):
            raise ValueError("Historical checksum mismatch")

        remaining = {
            path: checksum
            for path, checksum in original.items()
            if path not in retired
        }

        # Reconstruct the exact manifest produced by
        # the host retirement operation.
        removed_lines = {
            ("./" + path).encode("utf-8")
            for path in retired
        }

        expected = bytearray()

        for line in original_bytes.splitlines():
            if len(line) < 68 or line[64:66] != b"  ":
                raise ValueError(
                    "Unexpected historical manifest format"
                )

            if line[66:] not in removed_lines:
                expected.extend(line + b"\n")

        if _sha(expected) != after:
            raise ValueError(
                "Retirement manifest digest mismatch"
            )

        # Legitimate later registrations append new
        # checksum lines without altering existing lines.
        if not active_bytes.startswith(expected):
            continue

        if any(
            active.get(path) != checksum
            for path, checksum in remaining.items()
        ):
            raise ValueError(
                "Retained checksum was modified or removed"
            )

        if any(path in active for path in retired):
            raise ValueError(
                "Retired checksum was reintroduced"
            )

        if any(
            path in original
            for path in active
            if path not in remaining
        ):
            raise ValueError(
                "Original manifest path reintroduced"
            )

        matches.append(set(retired))

    if len(matches) != 1:
        raise ValueError(
            "Exactly one matching retirement receipt required"
        )

    return matches[0]
