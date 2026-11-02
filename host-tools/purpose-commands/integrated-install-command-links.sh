#!/bin/bash
set -euo pipefail

BASE="/boot/custom/cold-storage/integrated-v070"

for name in cold-register-sync cold-verify-sync; do
  source="$BASE/$name"
  target="/usr/local/bin/$name"

  if [[ ! -f "$source" || -L "$source" || ! -x "$source" ]]; then
    echo "STOP: Persistent command unavailable: $name" >&2
    exit 1
  fi

  if [[ -L "$target" ]]; then
    if [[ "$(readlink "$target")" != "$source" ]]; then
      echo "STOP: Unexpected existing shortcut: $name" >&2
      exit 1
    fi
  elif [[ -e "$target" ]]; then
    echo "STOP: Existing command must not be overwritten: $name" >&2
    exit 1
  else
    ln -s "$source" "$target"
  fi

  echo "$name: available"
done

# Restore purpose-specific Cold Storage commands.
/bin/bash /boot/custom/cold-storage/purpose-commands/install-purpose-commands.sh
