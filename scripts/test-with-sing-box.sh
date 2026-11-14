#!/bin/sh
set -eu

# The external core is started by the Rust fixtures as the protocol server;
# PathChord's native Transit adapter is always the client under test.

if [ -z "${PATHCHORD_TEST_SING_BOX:-}" ]; then
    echo "PATHCHORD_TEST_SING_BOX must point to an external sing-box test binary" >&2
    exit 2
fi
if [ ! -x "$PATHCHORD_TEST_SING_BOX" ]; then
    echo "PATHCHORD_TEST_SING_BOX is not executable: $PATHCHORD_TEST_SING_BOX" >&2
    exit 2
fi

exec cargo test --locked -p pathchord-transit --lib -- --ignored "$@"
