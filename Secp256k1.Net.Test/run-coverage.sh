#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
FRAMEWORK="${1:-net10.0}"
REPORT_DIR="$PROJECT_DIR/CoverageReport"

echo "Rebuilding test project..."
dotnet build "$SCRIPT_DIR" --configuration Release --framework "$FRAMEWORK" --force

echo "Running tests with coverage..."
dotnet test "$SCRIPT_DIR" --configuration Release --framework "$FRAMEWORK" --no-build \
    -p:CollectCoverage=true \
    -p:CoverletOutputFormat=cobertura \
    -p:CoverletOutput="$REPORT_DIR/coverage"

COVERAGE_FILE="$REPORT_DIR/coverage.$FRAMEWORK.cobertura.xml"

echo "Generating HTML report..."
dotnet tool exec dotnet-reportgenerator-globaltool --yes -- \
    -reports:"$COVERAGE_FILE" \
    -targetdir:"$REPORT_DIR" \
    -reporttypes:Html

echo "Coverage report generated at: $REPORT_DIR/index.html"

# Open the report if on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$REPORT_DIR/index.html"
elif [[ "$OSTYPE" == "linux-gnu"* ]] && command -v xdg-open &> /dev/null; then
    xdg-open "$REPORT_DIR/index.html"
fi
