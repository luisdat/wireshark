<#
.SYNOPSIS
    Wireshark build script (Final Version: Safe Directory & Interactive)
.DESCRIPTION
    - Full compile, link & installer generation.
    - Portable: Runs from the repository root.
    - Directory Safe: Returns to the original folder after execution.
    - Fixes MSB4057, RC1212, C11 SDK, and API changes.
#>

param (
    [switch]$Clean,          # Clean the 'build' directory before starting
    [switch]$Installer,      # Generate the NSIS Installer (.exe)
    [switch]$Ninja,          # Use Ninja generator (Experimental)
    [switch]$VS,             # Use Visual Studio generator (Recommended)
    [switch]$AllowWarnings   # Do not treat warnings as errors
)

$ErrorActionPreference = "Stop"

# ==========================================
# 0. CONFIGURATION (PORTABLE)
# ==========================================
$RepoRoot = $PSScriptRoot
$BuildDirName = "build" 
$BuildPath = Join-Path $RepoRoot $BuildDirName
$SourceDir = $RepoRoot

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Wireshark Build Script (Indra Edition)" -ForegroundColor Cyan
Write-Host " Repo Root:  $RepoRoot" -ForegroundColor Gray
Write-Host "==========================================" -ForegroundColor Cyan

# ==========================================
# 0.1 LIBS BASE DIRECTORY (INTERACTIVE)
# ==========================================
# Default: The directory above the repo (e.g. C:\dev if repo is C:\dev\wireshark)
$DefaultLibsPath = Split-Path -Parent $RepoRoot
$WiresharkBaseDir = $null

Write-Host "[LIBS] Default Base Directory: $DefaultLibsPath" -ForegroundColor Gray
Write-Host "Press ENTER to use default, or type a specific path." -ForegroundColor Yellow
$UserInput = Read-Host " > Base Dir [$DefaultLibsPath]"

if ([string]::IsNullOrWhiteSpace($UserInput)) {
    $WiresharkBaseDir = $DefaultLibsPath
    Write-Host "[LIBS] Using default: $WiresharkBaseDir" -ForegroundColor Green
} else {
    $CustomPath = $UserInput -replace '"', '' # Remove quotes
    while (-not (Test-Path $CustomPath)) {
        Write-Error "Path does not exist: $CustomPath"
        $CustomPath = Read-Host " > Please enter a valid path"
        $CustomPath = $CustomPath -replace '"', ''
    }
    $WiresharkBaseDir = $CustomPath
    Write-Host "[LIBS] Custom path accepted: $WiresharkBaseDir" -ForegroundColor Green
}

# ==========================================
# 0.2 QT PATH DETECTION
# ==========================================
$DefaultQtPath = "C:/dev/qt/6.9.3/msvc2022_64"
$QtPath = $null

if (Test-Path $DefaultQtPath) {
    Write-Host "[QT]   Found at default location: $DefaultQtPath" -ForegroundColor Green
    $QtPath = $DefaultQtPath
} else {
    Write-Warning "[QT] Default path not found ($DefaultQtPath)"
    Write-Host "Please enter the absolute path to Qt 6 (msvc2022_64)." -ForegroundColor Yellow
    
    while ($true) {
        $QtInput = Read-Host " > Qt Path"
        $QtInput = $QtInput -replace '"', ''
        
        if (Test-Path $QtInput) {
            $QtPath = $QtInput
            Write-Host "[QT] Valid path accepted." -ForegroundColor Green
            break
        } else {
            Write-Error "Path does not exist. Please try again."
        }
    }
}

# Ensure forward slashes for CMake compatibility
$QtPath = $QtPath -replace '\\', '/'

# Set Environment Variables
$env:WIRESHARK_BASE_DIR = $WiresharkBaseDir
$env:CMAKE_PREFIX_PATH = $QtPath
$env:WIRESHARK_QT6_PREFIX_PATH = $QtPath
$env:WIRESHARK_VERSION_EXTRA = "-Indra"

# ==========================================
# 0.3 FLAG MANAGEMENT
# ==========================================
$IgnoredWarnings = @(
    "/wd4996", # Qt Deprecated
    "/wd5286", # Enum conversion
    "/wd5287"  # Enum operands
)
$WarningString = $IgnoredWarnings -join " "

$env:CFLAGS = $WarningString
$env:CXXFLAGS = $WarningString

# ==========================================
# 1. ENVIRONMENT & ARCHITECTURE CHECK
# ==========================================
# 1. Check if cl.exe (Compiler) is available
if (-not (Get-Command "cl.exe" -ErrorAction SilentlyContinue)) {
    Write-Host "===============================================================" -ForegroundColor Red
    Write-Host " [ERROR] VISUAL STUDIO ENVIRONMENT NOT DETECTED" -ForegroundColor Red
    Write-Host "===============================================================" -ForegroundColor Red
    Write-Host " You are running this script in a standard PowerShell terminal." -ForegroundColor Yellow
    Write-Host " The build requires the MSVC compiler (cl.exe)." -ForegroundColor Yellow
    Write-Host ""
    Write-Host " HOW TO FIX:" -ForegroundColor Green
    Write-Host " 1. Close this terminal."
    Write-Host " 2. Press Windows Key and type: x64 Native Tools Command Prompt"
    Write-Host " 3. Open that terminal."
    Write-Host " 4. Type 'powershell' inside it and run this script again."
    Write-Host "===============================================================" -ForegroundColor Red
    exit 1
}

# 2. Check if the environment is strictly x64
if ($env:VSCMD_ARG_TGT_ARCH -ne "x64") {
    $clOutput = & cl.exe 2>&1 | Out-String
    if ($clOutput -match "x86" -and $clOutput -notmatch "x64") {
        Write-Host "===============================================================" -ForegroundColor Red
        Write-Host " [ERROR] WRONG ARCHITECTURE DETECTED (x86 / 32-bit)" -ForegroundColor Red
        Write-Host "===============================================================" -ForegroundColor Red
        Write-Host " You are using the 32-bit compiler." -ForegroundColor Yellow
        Write-Host " Wireshark requires 64-bit compilation." -ForegroundColor Yellow
        Write-Host " Please open: 'x64 Native Tools Command Prompt for VS 2022'" -ForegroundColor Green
        Write-Host "===============================================================" -ForegroundColor Red
        exit 1
    }
}

Write-Host "[SYSTEM] x64 Compiler Environment Detected." -ForegroundColor Cyan

# ==========================================
# 2. AUTO-DETECT WINDOWS SDK
# ==========================================
$SdkPaths = @("C:\Program Files (x86)\Windows Kits\10\Include", "C:\Program Files\Windows Kits\10\Include")
$LatestSdkVersion = $null

foreach ($path in $SdkPaths) {
    if (Test-Path $path) {
        $Ver = Get-ChildItem -Path $path -Directory | 
               Where-Object { $_.Name -like "10.*" } | 
               Sort-Object Name -Descending | 
               Select-Object -First 1 -ExpandProperty Name
        if ($Ver) { $LatestSdkVersion = $Ver; break }
    }
}

if ($LatestSdkVersion) {
    if (-not $LatestSdkVersion.EndsWith("\")) { $LatestSdkVersion = "$LatestSdkVersion\" }
    $env:WindowsSDKVersion = $LatestSdkVersion
    $env:WindowsSDKLibVersion = $LatestSdkVersion
    Write-Host "[SDK] Forced to: $LatestSdkVersion" -ForegroundColor Cyan
}

# ==========================================
# 3. DETERMINE MODE
# ==========================================
$IsNinja = $false
if ($Ninja) {
    if (Get-Command "ninja.exe" -ErrorAction SilentlyContinue) {
        $IsNinja = $true
        Write-Host "[SYSTEM] NINJA (x64)" -ForegroundColor Cyan
    } else {
        Write-Error "Ninja not found."
        exit 1
    }
} else {
    Write-Host "[SYSTEM] VISUAL STUDIO" -ForegroundColor Cyan
}

$WErrorValue = "ON"
if ($AllowWarnings) {
    $WErrorValue = "OFF"
    Write-Host "[MODE] PERMISSIVE (Warnings allowed)" -ForegroundColor Yellow
}

# ==========================================
# 4. CACHE MANAGEMENT & NAVIGATION
# ==========================================
if ($Clean) {
    if (Test-Path $BuildPath) {
        Write-Host "Cleaning build directory..." -ForegroundColor Yellow
        Remove-Item -Path $BuildPath -Recurse -Force
    }
}

if (-not (Test-Path $BuildPath)) { New-Item -Path $BuildPath -ItemType Directory | Out-Null }

# Store location to stack and move to build dir
Push-Location $BuildPath

try {
    # Auto-clean cache logic if generator changes
    if (Test-Path "CMakeCache.txt") {
        $CacheContent = Get-Content "CMakeCache.txt" | Out-String
        $PrevWasNinja = $CacheContent -match "CMAKE_GENERATOR:INTERNAL=Ninja"
        $Conflict = ($IsNinja -and -not $PrevWasNinja) -or (-not $IsNinja -and $PrevWasNinja)

        if ($Conflict) {
            Write-Warning "Generator change detected. Cleaning CMake cache..."
            Remove-Item "CMakeCache.txt" -Force -ErrorAction SilentlyContinue
            if (Test-Path "CMakeFiles") { Remove-Item "CMakeFiles" -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    # ==========================================
    # 5. CMAKE CONFIGURATION
    # ==========================================
    Write-Host "Configuring CMake..." -ForegroundColor Green

    $Generator = "Visual Studio 18 2026"
    $Arch = "x64"
    if ($IsNinja) { $Generator = "Ninja" }

    $SdkArg = $LatestSdkVersion.TrimEnd("\")

    $CMakeArgs = @(
        "-G", $Generator,
        "-DENABLE_WERROR=$WErrorValue",
        "-DCMAKE_RC_FLAGS='-DWIN32'"
    )

    if ($LatestSdkVersion) {
        $CMakeArgs += "-DCMAKE_SYSTEM_VERSION=$SdkArg"
        $CMakeArgs += "-DCMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION=$SdkArg"
    }

    if ($IsNinja) {
        $CMakeArgs += "-DCMAKE_BUILD_TYPE=RelWithDebInfo"
    } else {
        $CMakeArgs += "-A", $Arch
    }

    $CMakeArgs += $SourceDir

    & cmake $CMakeArgs
    if ($LASTEXITCODE -ne 0) { 
        throw "CMake configuration failed." 
    }

    # ==========================================
    # 6. BUILD
    # ==========================================
    Write-Host "Building project..." -ForegroundColor Green

    if ($IsNinja) {
        & ninja
    } else {
        & msbuild /m /p:Configuration=RelWithDebInfo Wireshark.sln
    }

    if ($LASTEXITCODE -ne 0) { throw "Build failed." }

    # ==========================================
    # 7. INSTALLER
    # ==========================================
    if ($Installer) {
        Write-Host "Generating Installer..." -ForegroundColor Magenta
        
        # Explicitly build the preparation target first
        & msbuild /m /p:Configuration=RelWithDebInfo wireshark_nsis_prep.vcxproj
        
        if ($LASTEXITCODE -eq 0) {
           # Build the final NSIS package target
           & msbuild /m /p:Configuration=RelWithDebInfo wireshark_nsis.vcxproj
        } else {
           Write-Error "Error preparing installer prerequisites." 
        }
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "=========================================" -ForegroundColor Green
            Write-Host " INSTALLER CREATED SUCCESSFULLY! " -ForegroundColor Green
            Write-Host " Location: $BuildPath\packaging\nsis" -ForegroundColor Green
            Write-Host "=========================================" -ForegroundColor Green
        } else {
            Write-Warning "Failed to create installer."
            Write-Warning "Is NSIS 3.x installed? (Run: winget install NSIS.NSIS)"
        }
    }

    Write-Host "Build Process Completed Successfully." -ForegroundColor Green

}
catch {
    Write-Error $_
}
finally {
    # RESTORE ORIGINAL LOCATION
    # This block always runs, even if compilation crashes
    Pop-Location
    Write-Host "[SYSTEM] Returned to original directory." -ForegroundColor Gray
}