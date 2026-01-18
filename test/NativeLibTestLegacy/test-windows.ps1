# Test legacy .NET Framework build on Windows
# Usage: .\test-windows.ps1 [-Arch x64|x86]
#
# Prerequisites:
#   - .NET Framework 4.6.2 or later (included in Windows 10+)
#   - .NET SDK for building
param(
    [ValidateSet("x64", "x86")]
    [string]$Arch = "x64"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path "$ScriptDir/../..").Path
Set-Location $ScriptDir

Write-Host "========================================"
Write-Host "Testing legacy .NET Framework on Windows ($Arch)"
Write-Host "========================================"
Write-Host ""

function Build-Package {
    Write-Host "==> Building Secp256k1.Net NuGet package..."
    dotnet pack "$RepoRoot/Secp256k1.Net" -c Release -o "$RepoRoot/pkg" -p:Version=0.0.1-localtest.1
    if ($LASTEXITCODE -ne 0) { throw "Package build failed" }
}

function Build-Legacy {
    Write-Host "==> Building legacy .NET Framework project..."
    # Clear all NuGet caches to ensure fresh package is used
    dotnet nuget locals all --clear 2>$null
    Remove-Item -Recurse -Force obj, bin -ErrorAction SilentlyContinue

    # Debug: Show package contents
    Write-Host "Debug: Package contents..."
    $pkgPath = "$RepoRoot/pkg/Secp256k1.Net.0.0.1-localtest.1.nupkg"
    if (Test-Path $pkgPath) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($pkgPath)
        $zip.Entries | Where-Object { $_.FullName -match "native|secp256k1" } | ForEach-Object {
            Write-Host "  $($_.FullName) (Size: $($_.Length))"
        }
        $zip.Dispose()
    }
    Write-Host ""

    dotnet build -c Release -p:PlatformTarget=$Arch
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }

    # Debug: Show directory structure after build
    Write-Host "Debug: Directory structure after build..."
    $outputDir = "$ScriptDir/bin/Release/net462"

    # Check for runtimes folder
    $runtimesPath = "$outputDir/runtimes"
    if (Test-Path $runtimesPath) {
        Write-Host "  runtimes/ folder exists:"
        Get-ChildItem -Path $runtimesPath -Recurse -File | ForEach-Object {
            $relativePath = $_.FullName.Substring($outputDir.Length + 1)
            Write-Host "    $relativePath (Size: $($_.Length))"
        }
    } else {
        Write-Host "  WARNING: runtimes/ folder does NOT exist!"
    }

    # Check for any .dll/.so/.dylib in root
    Write-Host "  Root native files:"
    Get-ChildItem -Path $outputDir -File | Where-Object { $_.Extension -in ".dll", ".so", ".dylib" } | ForEach-Object {
        Write-Host "    $($_.Name) (Size: $($_.Length))"
    }
    Write-Host ""
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
