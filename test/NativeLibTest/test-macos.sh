#!/bin/bash
# Test builds on macOS (run natively on macOS CI runner or local machine)
# Usage: ./test-macos.sh [portable|rid|singlefile|aot|all]
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$SCRIPT_DIR"

BUILD_MODE="${1:-all}"  # portable, rid, or all

# Detect current macOS architecture
ARCH=$(uname -m)
if [ "$ARCH" == "arm64" ]; then
    RID="osx-arm64"
    NATIVE_LIB="libsecp256k1.dylib"
else
    RID="osx-x64"
    NATIVE_LIB="libsecp256k1.dylib"
fi

echo "Detected macOS architecture: $ARCH (RID: $RID)"

build_package() {
    echo "==> Building Secp256k1.Net NuGet package..."
    # Clear any cached version of the local test package from global cache
    rm -rf ~/.nuget/packages/secp256k1.net/0.0.1-localtest.1
    dotnet pack "$REPO_ROOT/Secp256k1.Net" -c Release -o "$REPO_ROOT/pkg" -p:Version=0.0.1-localtest.1
}

test_portable() {
    local output_dir="$SCRIPT_DIR/publish/portable-macos"

    echo "--- Testing portable build ---"
    rm -rf "$output_dir"

    dotnet nuget locals http-cache --clear > /dev/null 2>&1 || true
    rm -rf obj bin
    dotnet publish -c Release -o "$output_dir"

    # Verify runtimes folder exists with all platforms
    if [ ! -d "$output_dir/runtimes" ]; then
        echo "FAILED: runtimes folder not found in portable build"
        return 1
    fi

    local runtime_count
    runtime_count=$(find "$output_dir/runtimes" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
    echo "Found $runtime_count runtime folders"

    # Run the test
    echo "Running test..."
    if dotnet "$output_dir/NativeLibTest.dll"; then
        echo "--- Portable: PASSED ---"
        echo
        return 0
    else
        echo "--- Portable: FAILED ---"
        echo
        return 1
    fi
}

test_rid_specific() {
    local output_dir="$SCRIPT_DIR/publish/rid-$RID"

    echo "--- Testing RID-specific build for $RID ---"
    rm -rf "$output_dir"

    dotnet nuget locals http-cache --clear > /dev/null 2>&1 || true
    rm -rf obj bin
    dotnet publish -c Release -r "$RID" --self-contained false -o "$output_dir"

    # Verify only single native library is present
    echo "Verifying single native library..."

    if [ -d "$output_dir/runtimes" ]; then
        echo "FAILED: Found 'runtimes' directory in RID-specific publish"
        ls -la "$output_dir/runtimes/" 2>/dev/null || true
        return 1
    fi

    local native_count
    native_count=$(find "$output_dir" -maxdepth 1 -type f \( -name "*.dylib" -o -name "*.so" -o -name "secp256k1.dll" \) | wc -l | tr -d ' ')

    if [ "$native_count" -ne 1 ]; then
        echo "FAILED: Expected 1 native library, found $native_count"
        echo "Files in publish directory:"
        ls -la "$output_dir"
        return 1
    fi

    if [ ! -f "$output_dir/$NATIVE_LIB" ]; then
        echo "FAILED: Expected $NATIVE_LIB not found"
        echo "Files in publish directory:"
        ls -la "$output_dir"
        return 1
    fi

    echo "OK: Found exactly $NATIVE_LIB"

    # Run the test
    echo "Running test..."
    if dotnet "$output_dir/NativeLibTest.dll"; then
        echo "--- RID-specific $RID: PASSED ---"
        echo
        return 0
    else
        echo "--- RID-specific $RID: FAILED ---"
        echo
        return 1
    fi
}

test_singlefile() {
    local output_dir="$SCRIPT_DIR/publish/singlefile-$RID"

    echo "--- Testing single-file build for $RID ---"
    rm -rf "$output_dir"

    dotnet nuget locals http-cache --clear > /dev/null 2>&1 || true
    rm -rf obj bin
    dotnet publish -c Release -r "$RID" --self-contained -p:PublishSingleFile=true -o "$output_dir"

    # Verify only single native library is present (alongside the single-file executable)
    echo "Verifying single native library..."

    if [ -d "$output_dir/runtimes" ]; then
        echo "FAILED: Found 'runtimes' directory in single-file publish"
        ls -la "$output_dir/runtimes/" 2>/dev/null || true
        return 1
    fi

    local native_count
    native_count=$(find "$output_dir" -maxdepth 1 -type f -name "*.dylib" | wc -l | tr -d ' ')

    if [ "$native_count" -ne 1 ]; then
        echo "FAILED: Expected 1 native library (.dylib), found $native_count"
        echo "Files in publish directory:"
        ls -la "$output_dir"
        return 1
    fi

    if [ ! -f "$output_dir/$NATIVE_LIB" ]; then
        echo "FAILED: Expected $NATIVE_LIB not found"
        echo "Files in publish directory:"
        ls -la "$output_dir"
        return 1
    fi

    # Verify single-file executable exists
    if [ ! -f "$output_dir/NativeLibTest" ]; then
        echo "FAILED: Single-file executable not found"
        echo "Files in publish directory:"
        ls -la "$output_dir"
        return 1
    fi

    echo "OK: Found $NATIVE_LIB and NativeLibTest executable"

    # Run the single-file executable directly (not via dotnet)
    echo "Running single-file test..."
    if "$output_dir/NativeLibTest"; then
        echo "--- Single-file $RID: PASSED ---"
        echo
        return 0
    else
        echo "--- Single-file $RID: FAILED ---"
        echo
        return 1
    fi
}

test_aot() {
    local output_dir="$SCRIPT_DIR/publish/aot-$RID"

    echo "--- Testing Native AOT build for $RID ---"
    rm -rf "$output_dir"

    dotnet nuget locals http-cache --clear > /dev/null 2>&1 || true
    rm -rf obj bin
    dotnet publish -c Release -r "$RID" -p:PublishAot=true -o "$output_dir"

    # Verify only single native library is present (alongside the AOT executable)
    echo "Verifying single native library..."

    if [ -d "$output_dir/runtimes" ]; then
        echo "FAILED: Found 'runtimes' directory in AOT publish"
        ls -la "$output_dir/runtimes/" 2>/dev/null || true
        return 1
    fi

    local native_count
    native_count=$(find "$output_dir" -maxdepth 1 -type f -name "*.dylib" | wc -l | tr -d ' ')

    if [ "$native_count" -ne 1 ]; then
        echo "FAILED: Expected 1 native library (.dylib), found $native_count"
        echo "Files in publish directory:"
        ls -la "$output_dir"
        return 1
    fi

    if [ ! -f "$output_dir/$NATIVE_LIB" ]; then
        echo "FAILED: Expected $NATIVE_LIB not found"
        echo "Files in publish directory:"
        ls -la "$output_dir"
        return 1
    fi

    # Verify native AOT executable exists
    if [ ! -f "$output_dir/NativeLibTest" ]; then
        echo "FAILED: Native AOT executable not found"
        echo "Files in publish directory:"
        ls -la "$output_dir"
        return 1
    fi

    echo "OK: Found $NATIVE_LIB and NativeLibTest executable"

    # Run the native AOT executable directly (not via dotnet)
    echo "Running native AOT test..."
    if "$output_dir/NativeLibTest"; then
        echo "--- Native AOT $RID: PASSED ---"
        echo
        return 0
    else
        echo "--- Native AOT $RID: FAILED ---"
        echo
        return 1
    fi
}

# Main
failed=0

echo "========================================"
echo "Testing on macOS"
echo "========================================"
echo

build_package

case "$BUILD_MODE" in
    portable)
        test_portable || failed=1
        ;;
    rid)
        test_rid_specific || failed=1
        ;;
    singlefile)
        test_singlefile || failed=1
        ;;
    aot)
        test_aot || failed=1
        ;;
    all)
        test_portable || failed=1
        test_rid_specific || failed=1
        test_singlefile || failed=1
        test_aot || failed=1
        ;;
    *)
        echo "Unknown build mode: $BUILD_MODE"
        echo "Usage: $0 [portable|rid|singlefile|aot|all]"
        exit 1
        ;;
esac

if [ $failed -eq 0 ]; then
    echo "========================================"
    echo "All macOS tests passed!"
    echo "========================================"
else
    echo "========================================"
    echo "Some tests failed!"
    echo "========================================"
    exit 1
fi
