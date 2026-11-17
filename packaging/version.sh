#!/bin/sh
# Print the workspace version used by every native package recipe.
set -eu

root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
awk '
  /^\[workspace\.package\]$/ { in_workspace_package = 1; next }
  /^\[/ { in_workspace_package = 0 }
  in_workspace_package && $1 == "version" {
    value = $0
    sub(/^[^=]*=[[:space:]]*/, "", value)
    gsub(/[[:space:]"]/, "", value)
    print value
    found = 1
    exit
  }
  END { if (!found) exit 1 }
' "$root_dir/Cargo.toml"
