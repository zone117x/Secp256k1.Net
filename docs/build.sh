#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$SCRIPT_DIR"

# Copy README.md as index.md
cp "$ROOT_DIR/README.md" "$SCRIPT_DIR/index.md"

# Build the documentation
dotnet tool exec --yes docfx -- docfx.json "$@"

echo ""
echo "Documentation built successfully in docs/_site/"
echo "To preview, run: ./docs/build.sh --serve"
