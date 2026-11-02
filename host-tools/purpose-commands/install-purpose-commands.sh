#!/usr/bin/env bash
set -euo pipefail
BASE="/boot/custom/cold-storage/purpose-commands"
BIN="/usr/local/bin"
names=(cold-drive-add cold-sha256-create cold-sha256-verify cold-par2-create cold-par2-add cold-par2-plan cold-par2-verify)
# Validate all destinations before creating any links.
for name in "${names[@]}"; do
  source="$BASE/$name"
  target="$BIN/$name"
  [[ -f "$source" && ! -L "$source" && -x "$source" ]] || { echo "STOP: Missing launcher: $name" >&2; exit 1; }
  if [[ -L "$target" ]]; then
    [[ "$(readlink "$target")" == "$source" ]] || { echo "STOP: Unexpected shortcut: $name" >&2; exit 1; }
  elif [[ -e "$target" ]]; then
    echo "STOP: Existing command must not be overwritten: $name" >&2
    exit 1
  fi
done
for name in "${names[@]}"; do
  [[ -L "$BIN/$name" ]] || ln -s "$BASE/$name" "$BIN/$name"
  echo "$name: available"
done
