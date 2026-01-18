#!/bin/bash
# Test RID-specific builds on Linux via Docker
# Verifies that only the correct native library is included
# Usage: ./test-linux-rid.sh [rid]
# RIDs: all, linux-x64, linux-arm64, linux-musl-x64, linux-musl-arm64
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$SCRIPT_DIR"

RID="${1:-all}"

# Get Docker image for a RID (compatible with bash 3.x)
get_docker_image() {
    case "$1" in
        linux-x64|linux-arm64) echo "mcr.microsoft.com/dotnet/runtime:8.0" ;;
        linux-musl-x64|linux-musl-arm64) echo "mcr.microsoft.com/dotnet/runtime:8.0-alpine" ;;
    esac
}

# Get Docker platform for a RID (compatible with bash 3.x)
get_docker_platform() {
    case "$1" in
        linux-x64|linux-musl-x64) echo "linux/amd64" ;;
        linux-arm64|linux-musl-arm64) echo "linux/arm64" ;;
    esac
}

# Get expected native library name for a RID (compatible with bash 3.x)
get_native_lib() {
    # All Linux RIDs use the same library name
    echo "libsecp256k1.so"
}

RIDS_TO_TEST=""
if [ "$RID" = "all" ]; then
    RIDS_TO_TEST="linux-x64 linux-arm64 linux-musl-x64 linux-musl-arm64"
else
    RIDS_TO_TEST="$RID"
fi

build_package() {
    echo "==> Building Secp256k1.Net NuGet package..."
    dotnet pack "$REPO_ROOT/Secp256k1.Net" -c Release -o "$REPO_ROOT/pkg" -p:Version=0.0.1-localtest.1
}

publish_rid_specific() {
    local rid="$1"
    local output_dir="$SCRIPT_DIR/publish/rid-$rid"

    echo "==> Publishing RID-specific build for $rid..."
    rm -rf "$output_dir"

    dotnet nuget locals http-cache --clear > /dev/null 2>&1 || true
    rm -rf obj bin
    dotnet publish -c Release -r "$rid" --self-contained false -o "$output_dir"
}

verify_single_native() {
    local rid="$1"
    local publish_dir="$SCRIPT_DIR/publish/rid-$rid"
    local expected_lib
    expected_lib=$(get_native_lib "$rid")

    echo "--- Verifying $rid contains only single native library ---"

    # Check for runtimes folder (should not exist in RID-specific publish)
    if [ -d "$publish_dir/runtimes" ]; then
        echo "FAILED: Found 'runtimes' directory in RID-specific publish"
        ls -la "$publish_dir/runtimes/" 2>/dev/null || true
        return 1
    fi

    # Count native library files
    local native_count
    native_count=$(find "$publish_dir" -maxdepth 1 -type f \( -name "*.so" -o -name "*.dylib" -o -name "secp256k1.dll" \) | wc -l | tr -d ' ')

    # Should have exactly one native library
    if [ "$native_count" -ne 1 ]; then
        echo "FAILED: Expected 1 native library, found $native_count"
        echo "Files in publish directory:"
        ls -la "$publish_dir"
        return 1
    fi

    # Verify it's the correct library
    if [ ! -f "$publish_dir/$expected_lib" ]; then
        echo "FAILED: Expected $expected_lib not found"
        echo "Files in publish directory:"
        ls -la "$publish_dir"
        return 1
    fi

    echo "OK: Found exactly $expected_lib (no other natives)"
    return 0
}

run_docker_test() {
    local name="$1"
    local rid="$2"
    local image
    local docker_platform
    local publish_dir="$SCRIPT_DIR/publish/rid-$rid"

    image=$(get_docker_image "$rid")
    docker_platform=$(get_docker_platform "$rid")

    echo "--- Testing: $name (RID: $rid) ---"

    if docker run --rm --platform "$docker_platform" \
        -v "$publish_dir:/app:ro" \
        "$image" \
        dotnet /app/NativeLibTest.dll; then
        echo "--- $name ($rid): PASSED ---"
        echo
        return 0
    else
        echo "--- $name ($rid): FAILED ---"
        echo
        return 1
    fi
}

test_rid() {
    local rid="$1"
    local failed=0

    publish_rid_specific "$rid"

    # Verify only single native library is present
    if ! verify_single_native "$rid"; then
        return 1
    fi

    # Run functional test
    case "$rid" in
        linux-x64)
            run_docker_test "Linux x64 (glibc)" "$rid" || failed=1
            ;;
        linux-arm64)
            run_docker_test "Linux ARM64 (glibc)" "$rid" || failed=1
            ;;
        linux-musl-x64)
            run_docker_test "Linux x64 (musl/Alpine)" "$rid" || failed=1
            ;;
        linux-musl-arm64)
            run_docker_test "Linux ARM64 (musl/Alpine)" "$rid" || failed=1
            ;;
    esac

    return $failed
}

# Main
failed=0

echo "========================================"
echo "Testing RID-specific Linux builds"
echo "========================================"
echo

build_package

for rid in $RIDS_TO_TEST; do
    test_rid "$rid" || failed=1
done

if [ $failed -eq 0 ]; then
    echo "========================================"
    echo "All RID-specific Linux tests passed!"
    echo "========================================"
else
    echo "========================================"
    echo "Some tests failed!"
    echo "========================================"
    exit 1
fi
