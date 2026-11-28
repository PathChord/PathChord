#!/bin/sh
# Print the package version for this checkout or prebuilt binary assembly.
set -eu

version=${PATHCHORD_VERSION:-}
if [ -z "$version" ]; then
    root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
    version=$(awk '
        /^[[:space:]]*\[workspace\.package\][[:space:]]*(#.*)?$/ { workspace = 1; next }
        /^[[:space:]]*\[/ { workspace = 0 }
        workspace && /^[[:space:]]*version[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, "")
            quote = substr($0, 1, 1)
            if (quote != "\"" && quote != sprintf("%c", 39)) exit
            end = index(substr($0, 2), quote)
            if (end && substr($0, end + 2) ~ /^[[:space:]]*(#.*)?$/) print substr($0, 2, end - 1)
            exit
        }
    ' "$root_dir/Cargo.toml")
fi
case "$version" in
    ''|[!0-9]*|*[!0-9A-Za-z.+:~_-]*)
        echo 'invalid or missing package version; check PATHCHORD_VERSION or [workspace.package].version' >&2
        exit 2 ;;
esac
printf '%s\n' "$version"
