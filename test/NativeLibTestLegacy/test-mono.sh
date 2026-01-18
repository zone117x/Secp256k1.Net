#!/bin/bash
# Test legacy .NET Framework build using Mono on Linux/macOS
# Usage: ./test-mono.sh
#
# Prerequisites:
#   - Mono must be installed (https://www.mono-project.com/download/stable/)
#   - On macOS: brew install mono
#   - On Linux: apt-get install mono-complete (or equivalent)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$SCRIPT_DIR"

# Check for Mono
if ! command -v mono &> /dev/null; then
    echo "ERROR: Mono is not installed or not in PATH"
    echo "Install Mono from: https://www.mono-project.com/download/stable/"
    exit 1
fi

echo "========================================"
echo "Testing legacy .NET Framework with Mono"
echo "========================================"
echo
echo "Mono version: $(mono --version | head -1)"
echo

build_package() {
    echo "==> Building Secp256k1.Net NuGet package..."
    dotnet pack "$REPO_ROOT/Secp256k1.Net" -c Release -o "$REPO_ROOT/pkg" -p:Version=0.0.1-localtest.1
}

build_legacy() {
    echo "==> Building legacy .NET Framework project..."
    dotnet nuget locals http-cache --clear > /dev/null 2>&1 || true
    rm -rf obj bin
    dotnet build -c Release
}

run_test() {
    local output_dir="$SCRIPT_DIR/bin/Release/net462"

    echo "==> Running test with Mono..."
    echo

    # Run with Mono - the library probes for the correct native library at runtime
    if mono "$output_dir/NativeLibTestLegacy.exe"; then
        echo
        echo "========================================"
        echo "Legacy .NET Framework test passed!"
        echo "========================================"
        return 0
    else
        echo
        echo "========================================"
        echo "Test FAILED!"
        echo "========================================"
        return 1
    fi
}

# Main
build_package
build_legacy
run_test
