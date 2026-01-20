#!/bin/bash
# Test portable (cross-platform) builds on Linux via Docker
# Usage: ./test-linux-portable.sh [platform]
# Platforms: all, linux-x64, linux-arm64, linux-musl-x64, linux-musl-arm64
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$SCRIPT_DIR"

PLATFORM="${1:-all}"

# Get Docker image for a platform (compatible with bash 3.x)
get_docker_image() {
    case "$1" in
        linux-x64|linux-arm64) echo "mcr.microsoft.com/dotnet/runtime:10.0" ;;
        linux-musl-x64|linux-musl-arm64) echo "mcr.microsoft.com/dotnet/runtime:10.0-alpine" ;;
    esac
}

# Get Docker platform for a RID (compatible with bash 3.x)
get_docker_platform() {
    case "$1" in
        linux-x64|linux-musl-x64) echo "linux/amd64" ;;
        linux-arm64|linux-musl-arm64) echo "linux/arm64" ;;
    esac
}

PLATFORMS_TO_TEST=""
if [ "$PLATFORM" = "all" ]; then
    PLATFORMS_TO_TEST="linux-x64 linux-arm64 linux-musl-x64 linux-musl-arm64"
else
    PLATFORMS_TO_TEST="$PLATFORM"
fi

build_package() {
    echo "==> Building Secp256k1.Net NuGet package..."
    dotnet pack "$REPO_ROOT/Secp256k1.Net" -c Release -o "$REPO_ROOT/pkg" -p:Version=0.0.1-localtest.1
}

publish_portable() {
    local output_dir="$SCRIPT_DIR/publish/portable"

    echo "==> Publishing portable build..."
    rm -rf "$output_dir"

    dotnet nuget locals http-cache --clear > /dev/null 2>&1 || true
    rm -rf obj bin
    dotnet publish -c Release -o "$output_dir"
}

run_docker_test() {
    local name="$1"
    local rid="$2"
    local image
    local docker_platform
    local publish_dir="$SCRIPT_DIR/publish/portable"

    image=$(get_docker_image "$rid")
    docker_platform=$(get_docker_platform "$rid")

    echo "--- Testing: $name ---"

    if docker run --rm --platform "$docker_platform" \
        -v "$publish_dir:/app:ro" \
        "$image" \
        dotnet /app/NativeLibTest.dll; then
        echo "--- $name: PASSED ---"
        echo
        return 0
    else
        echo "--- $name: FAILED ---"
        echo
        return 1
    fi
}

# Main
failed=0

echo "========================================"
echo "Testing portable Linux builds"
echo "========================================"
echo

build_package
publish_portable

for rid in $PLATFORMS_TO_TEST; do
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
done

if [ $failed -eq 0 ]; then
    echo "========================================"
    echo "All portable Linux tests passed!"
    echo "========================================"
else
    echo "========================================"
    echo "Some tests failed!"
    echo "========================================"
    exit 1
fi
