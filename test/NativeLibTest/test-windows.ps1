# Test builds on Windows (run on Windows CI runner)
# Usage: .\test-windows.ps1 [-BuildMode portable|rid|all]
param(
    [ValidateSet("portable", "rid", "all")]
    [string]$BuildMode = "all"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path "$ScriptDir/../..").Path
Set-Location $ScriptDir

# Detect Windows architecture
$Arch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
switch ($Arch) {
    "Arm64" {
        $RID = "win-arm64"
    }
    "X64" {
        $RID = "win-x64"
    }
    "X86" {
        $RID = "win-x86"
    }
    default {
        $RID = "win-x64"
    }
}
$NativeLib = "secp256k1.dll"

Write-Host "Detected Windows architecture: $Arch (RID: $RID)"

function Build-Package {
    Write-Host "==> Building Secp256k1.Net NuGet package..."
    dotnet pack "$RepoRoot/Secp256k1.Net" -c Release -o "$RepoRoot/pkg" -p:Version=0.0.1-localtest.1
    if ($LASTEXITCODE -ne 0) { throw "Package build failed" }
}

function Test-Portable {
    $OutputDir = "$ScriptDir/publish/portable-windows"

    Write-Host "--- Testing portable build ---"
    if (Test-Path $OutputDir) { Remove-Item -Recurse -Force $OutputDir }

    dotnet nuget locals http-cache --clear 2>$null
    if (Test-Path obj) { Remove-Item -Recurse -Force obj }
    if (Test-Path bin) { Remove-Item -Recurse -Force bin }
    dotnet publish -c Release -o $OutputDir
    if ($LASTEXITCODE -ne 0) { throw "Publish failed" }

    # Verify runtimes folder exists
    if (-not (Test-Path "$OutputDir/runtimes")) {
        Write-Host "FAILED: runtimes folder not found in portable build"
        return $false
    }

    $RuntimeCount = (Get-ChildItem "$OutputDir/runtimes" -Directory).Count
    Write-Host "Found $RuntimeCount runtime folders"

    # Run the test
    Write-Host "Running test..."
    dotnet "$OutputDir/NativeLibTest.dll"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "--- Portable: PASSED ---"
        Write-Host ""
        return $true
    } else {
        Write-Host "--- Portable: FAILED ---"
        Write-Host ""
        return $false
    }
}

function Test-RidSpecific {
    $OutputDir = "$ScriptDir/publish/rid-$RID"

    Write-Host "--- Testing RID-specific build for $RID ---"
    if (Test-Path $OutputDir) { Remove-Item -Recurse -Force $OutputDir }

    dotnet nuget locals http-cache --clear 2>$null
    if (Test-Path obj) { Remove-Item -Recurse -Force obj }
    if (Test-Path bin) { Remove-Item -Recurse -Force bin }
    dotnet publish -c Release -r $RID --self-contained false -o $OutputDir
    if ($LASTEXITCODE -ne 0) { throw "Publish failed" }

    # Verify only single native library is present
    Write-Host "Verifying single native library..."

    # Check for runtimes folder (should not exist)
    if (Test-Path "$OutputDir/runtimes") {
        Write-Host "FAILED: Found 'runtimes' directory in RID-specific publish"
        Get-ChildItem "$OutputDir/runtimes" -Recurse
        return $false
    }

    # Count native library files (excluding managed DLLs)
    $NativeFiles = Get-ChildItem $OutputDir -File | Where-Object {
        ($_.Extension -eq ".dll" -or $_.Extension -eq ".so" -or $_.Extension -eq ".dylib") -and
        $_.Name -ne "NativeLibTest.dll" -and
        $_.Name -ne "Secp256k1.Net.dll"
    }
    $NativeCount = ($NativeFiles | Measure-Object).Count

    if ($NativeCount -ne 1) {
        Write-Host "FAILED: Expected 1 native library, found $NativeCount"
        Write-Host "Files in publish directory:"
        Get-ChildItem $OutputDir
        return $false
    }

    if (-not (Test-Path "$OutputDir/$NativeLib")) {
        Write-Host "FAILED: Expected $NativeLib not found"
        Write-Host "Files in publish directory:"
        Get-ChildItem $OutputDir
        return $false
    }

    Write-Host "OK: Found exactly $NativeLib"

    # Run the test
    Write-Host "Running test..."
    dotnet "$OutputDir/NativeLibTest.dll"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "--- RID-specific ${RID}: PASSED ---"
        Write-Host ""
        return $true
    } else {
        Write-Host "--- RID-specific ${RID}: FAILED ---"
        Write-Host ""
        return $false
    }
}

# Main
$Failed = $false

Write-Host "========================================"
Write-Host "Testing on Windows"
Write-Host "========================================"
Write-Host ""

Build-Package

switch ($BuildMode) {
    "portable" {
        if (-not (Test-Portable)) { $Failed = $true }
    }
    "rid" {
        if (-not (Test-RidSpecific)) { $Failed = $true }
    }
    "all" {
        if (-not (Test-Portable)) { $Failed = $true }
        if (-not (Test-RidSpecific)) { $Failed = $true }
    }
}

if (-not $Failed) {
    Write-Host "========================================"
    Write-Host "All Windows tests passed!"
    Write-Host "========================================"
    exit 0
} else {
    Write-Host "========================================"
    Write-Host "Some tests failed!"
    Write-Host "========================================"
    exit 1
}
