#!/bin/bash
# Test Native AOT builds on Linux via Docker
# Verifies that AOT compilation works and produces working native executables
# Usage: ./test-linux-aot.sh [rid]
# RIDs: all, linux-x64, linux-arm64, linux-musl-x64, linux-musl-arm64
#
# Note: AOT compilation under QEMU emulation (e.g., linux-musl-x64 on ARM64 host)
# may crash due to ILC compiler issues with emulated memory. Tests that require
# cross-architecture emulation may be skipped.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$SCRIPT_DIR"

RID="${1:-all}"

# Detect host architecture to skip cross-arch AOT (which crashes under QEMU)
HOST_ARCH=$(uname -m)
is_native_arch() {
    local rid="$1"
    case "$HOST_ARCH" in
        x86_64|amd64)
            case "$rid" in
                linux-x64|linux-musl-x64) return 0 ;;
                *) return 1 ;;
            esac
            ;;
        arm64|aarch64)
            case "$rid" in
                linux-arm64|linux-musl-arm64) return 0 ;;
                *) return 1 ;;
            esac
            ;;
    esac
    return 1
}

# Get Docker SDK image for AOT compilation (compatible with bash 3.x)
get_sdk_image() {
    case "$1" in
        linux-x64|linux-arm64) echo "mcr.microsoft.com/dotnet/sdk:10.0" ;;
        linux-musl-x64|linux-musl-arm64) echo "mcr.microsoft.com/dotnet/sdk:10.0-alpine" ;;
    esac
}

# Get Docker runtime image for running the AOT binary (compatible with bash 3.x)
get_runtime_image() {
    case "$1" in
        linux-x64|linux-arm64) echo "mcr.microsoft.com/dotnet/runtime-deps:10.0" ;;
        linux-musl-x64|linux-musl-arm64) echo "mcr.microsoft.com/dotnet/runtime-deps:10.0-alpine" ;;
    esac
}

# Get Docker platform for a RID (compatible with bash 3.x)
get_docker_platform() {
    case "$1" in
        linux-x64|linux-musl-x64) echo "linux/amd64" ;;
        linux-arm64|linux-musl-arm64) echo "linux/arm64" ;;
    esac
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

publish_aot() {
    local rid="$1"
    local sdk_image
    local docker_platform
    local output_dir="$SCRIPT_DIR/publish/aot-$rid"

    sdk_image=$(get_sdk_image "$rid")
    docker_platform=$(get_docker_platform "$rid")

    echo "==> Publishing Native AOT build for $rid..."
    rm -rf "$output_dir"
    mkdir -p "$output_dir"

    # Clear caches and build artifacts
    dotnet nuget locals http-cache --clear > /dev/null 2>&1 || true
    rm -rf obj bin

    # AOT compilation must happen on the target platform, so we use Docker
    # Mount the repo and local package source, then publish inside the container
    docker run --rm --platform "$docker_platform" \
        -v "$REPO_ROOT:/repo:ro" \
        -v "$REPO_ROOT/pkg:/packages:ro" \
        -v "$output_dir:/output" \
        -w /build \
        "$sdk_image" \
        sh -c "
            # Install clang (required for AOT on Linux)
            if command -v apk > /dev/null 2>&1; then
                apk add --no-cache clang build-base zlib-dev
            else
                apt-get update && apt-get install -y clang zlib1g-dev
            fi

            # Copy project to writable location
            cp -r /repo/test/NativeLibTest/* /build/

            # Create nuget.config pointing to local packages
            cat > /build/nuget.config << 'NUGETEOF'
<?xml version=\"1.0\" encoding=\"utf-8\"?>
<configuration>
  <packageSources>
    <clear />
    <add key=\"local\" value=\"/packages\" />
    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />
  </packageSources>
</configuration>
NUGETEOF

            # Publish with AOT
            dotnet publish -c Release -r $rid -p:PublishAot=true -o /output
        " -- "$rid"
}

verify_aot_output() {
    local rid="$1"
    local publish_dir="$SCRIPT_DIR/publish/aot-$rid"

    echo "--- Verifying $rid AOT output ---"

    # Check for runtimes folder (should not exist in AOT publish)
    if [ -d "$publish_dir/runtimes" ]; then
        echo "FAILED: Found 'runtimes' directory in AOT publish"
        ls -la "$publish_dir/runtimes/" 2>/dev/null || true
        return 1
    fi

    # Count native library files (.so)
    local native_count
    native_count=$(find "$publish_dir" -maxdepth 1 -type f -name "*.so" | wc -l | tr -d ' ')

    if [ "$native_count" -ne 1 ]; then
        echo "FAILED: Expected 1 native library (.so), found $native_count"
        echo "Files in publish directory:"
        ls -la "$publish_dir"
        return 1
    fi

    if [ ! -f "$publish_dir/libsecp256k1.so" ]; then
        echo "FAILED: Expected libsecp256k1.so not found"
        echo "Files in publish directory:"
        ls -la "$publish_dir"
        return 1
    fi

    # Verify native AOT executable exists
    if [ ! -f "$publish_dir/NativeLibTest" ]; then
        echo "FAILED: Native AOT executable not found"
        echo "Files in publish directory:"
        ls -la "$publish_dir"
        return 1
    fi

    echo "OK: Found libsecp256k1.so and NativeLibTest executable"
    return 0
}

run_aot_test() {
    local name="$1"
    local rid="$2"
    local runtime_image
    local docker_platform
    local publish_dir="$SCRIPT_DIR/publish/aot-$rid"

    runtime_image=$(get_runtime_image "$rid")
    docker_platform=$(get_docker_platform "$rid")

    echo "--- Testing: $name (AOT, RID: $rid) ---"

    # Run the native executable directly (no dotnet needed)
    if docker run --rm --platform "$docker_platform" \
        -v "$publish_dir:/app:ro" \
        "$runtime_image" \
        /app/NativeLibTest; then
        echo "--- $name (AOT, $rid): PASSED ---"
        echo
        return 0
    else
        echo "--- $name (AOT, $rid): FAILED ---"
        echo
        return 1
    fi
}

test_aot_rid() {
    local rid="$1"
    local failed=0

    publish_aot "$rid"

    # Verify AOT output
    if ! verify_aot_output "$rid"; then
        return 1
    fi

    # Run functional test
    case "$rid" in
        linux-x64)
            run_aot_test "Linux x64 (glibc)" "$rid" || failed=1
            ;;
        linux-arm64)
            run_aot_test "Linux ARM64 (glibc)" "$rid" || failed=1
            ;;
        linux-musl-x64)
            run_aot_test "Linux x64 (musl/Alpine)" "$rid" || failed=1
            ;;
        linux-musl-arm64)
            run_aot_test "Linux ARM64 (musl/Alpine)" "$rid" || failed=1
            ;;
    esac

    return $failed
}

# Main
failed=0

echo "========================================"
echo "Testing Native AOT Linux builds"
echo "========================================"
echo

build_package

skipped=0
for rid in $RIDS_TO_TEST; do
    if ! is_native_arch "$rid"; then
        echo "==> Skipping $rid (AOT cross-compilation crashes under QEMU emulation on $HOST_ARCH)"
        echo
        skipped=$((skipped + 1))
        continue
    fi
    test_aot_rid "$rid" || failed=1
done

if [ $failed -eq 0 ]; then
    echo "========================================"
    if [ $skipped -gt 0 ]; then
        echo "Native AOT Linux tests passed! ($skipped skipped due to cross-arch)"
    else
        echo "All Native AOT Linux tests passed!"
    fi
    echo "========================================"
else
    echo "========================================"
    echo "Some tests failed!"
    echo "========================================"
    exit 1
fi
