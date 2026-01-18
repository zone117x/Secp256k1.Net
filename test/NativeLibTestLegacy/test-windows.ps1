# Test legacy .NET Framework build on Windows
# Usage: .\test-windows.ps1
#
# Prerequisites:
#   - .NET Framework 4.6.2 or later (included in Windows 10+)
#   - .NET SDK for building
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path "$ScriptDir/../..").Path
Set-Location $ScriptDir

Write-Host "========================================"
Write-Host "Testing legacy .NET Framework on Windows"
Write-Host "========================================"
Write-Host ""

function Build-Package {
    Write-Host "==> Building Secp256k1.Net NuGet package..."
    dotnet pack "$RepoRoot/Secp256k1.Net" -c Release -o "$RepoRoot/pkg" -p:Version=0.0.1-localtest.1
    if ($LASTEXITCODE -ne 0) { throw "Package build failed" }
}

function Build-Legacy {
    Write-Host "==> Building legacy .NET Framework project..."
    dotnet nuget locals http-cache --clear 2>$null
    Remove-Item -Recurse -Force obj, bin -ErrorAction SilentlyContinue
    dotnet build -c Release
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
}

function Run-Test {
    $OutputDir = "$ScriptDir/bin/Release/net462"

    Write-Host "==> Running test..."
    Write-Host ""

    # Debug: show output directory contents related to secp256k1
    Write-Host "Debug: Checking for secp256k1 files..."
    Get-ChildItem -Path $OutputDir -Recurse -Filter "*secp256k1*" | ForEach-Object {
        Write-Host "  Found: $($_.FullName) (Size: $($_.Length))"
    }
    Write-Host ""

    # Run the executable - the library probes for the correct native library at runtime
    $exe = "$OutputDir/NativeLibTestLegacy.exe"
    & $exe
    $exitCode = $LASTEXITCODE

    Write-Host ""
    if ($exitCode -eq 0) {
        Write-Host "========================================"
        Write-Host "Legacy .NET Framework test passed!"
        Write-Host "========================================"
    } else {
        Write-Host "========================================"
        Write-Host "Test FAILED!"
        Write-Host "========================================"
        exit $exitCode
    }
}

# Main
try {
    Build-Package
    Build-Legacy
    Run-Test
} catch {
    Write-Host "ERROR: $_"
    exit 1
}
