#!/bin/sh
set -eu

core_kind=${PATHCHORD_TEST_CORE_KIND:-}
case "$core_kind" in
    mihomo)
        binary_var=PATHCHORD_TEST_MIHOMO
        binary=${PATHCHORD_TEST_MIHOMO:-}
        test_name=pathchord_client_interoperates_with_mihomo_server
        ;;
    xray)
        binary_var=PATHCHORD_TEST_XRAY
        binary=${PATHCHORD_TEST_XRAY:-}
        test_name=pathchord_client_interoperates_with_xray_server
        ;;
    v2fly)
        binary_var=PATHCHORD_TEST_V2FLY
        binary=${PATHCHORD_TEST_V2FLY:-}
        test_name=pathchord_client_interoperates_with_v2fly_server
        ;;
    *)
        echo "PATHCHORD_TEST_CORE_KIND must be mihomo, xray, or v2fly" >&2
        exit 2
        ;;
esac
if [ -z "$binary" ]; then
    echo "$binary_var must point to an external server binary" >&2
    exit 2
fi
if [ ! -x "$binary" ]; then
    echo "$binary_var is not executable: $binary" >&2
    exit 2
fi

env "$binary_var=$binary" cargo test --locked -p pathchord-transit \
    --test external_core_servers -- --ignored "$test_name" "$@"
