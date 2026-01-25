<#
.SYNOPSIS
    Wireshark build script (Smart Caching Version)
.DESCRIPTION
    - Full compile, link & installer generation.
    - Smart Build: Skips CMake if generator and flags haven't changed.
    - Auto-switches between Ninja and VS transparently.
    - Fixes MSB4057, RC1212, C11 SDK, and API changes.
#>

param (
    [string]$Base,           # OPTIONAL: Path to the libs parent folder (skips prompt)
    [switch]$Clean,          # Clean the 'build' directory before starting
    [switch]$Installer,      # Generate the NSIS Installer (.exe)
    [switch]$Ninja,          # Use Ninja generator (Experimental)
    [switch]$VS,             # Use Visual Studio generator (Recommended)
    [switch]$AllowWarnings,  # Do not treat warnings as errors
    [switch]$ForceCMake      # Force CMake reconfiguration manually
)

$ErrorActionPreference = "Stop"

# ==========================================
# 0. CONFIGURATION
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
# 0.1 LIBS BASE DIRECTORY
# ==========================================
$WiresharkBaseDir = $null

if (-not [string]::IsNullOrWhiteSpace($Base)) {
    $CustomPath = $Base -replace '"', ''
    if (Test-Path $CustomPath) {
        $WiresharkBaseDir = $CustomPath
        Write-Host "[LIBS] Using provided base argument: $WiresharkBaseDir" -ForegroundColor Green
    }
    else {
        Write-Error "The provided -Base path does not exist: $CustomPath"
        exit 1
    }
}
else {
    $DefaultLibsPath = Split-Path -Parent $RepoRoot
    Write-Host "[LIBS] Default Base Directory: $DefaultLibsPath" -ForegroundColor Gray
    Write-Host "Press ENTER to use default, or type a specific path." -ForegroundColor Yellow
    $UserInput = Read-Host " > Base Dir [$DefaultLibsPath]"

    if ([string]::IsNullOrWhiteSpace($UserInput)) {
        $WiresharkBaseDir = $DefaultLibsPath
        Write-Host "[LIBS] Using default: $WiresharkBaseDir" -ForegroundColor Green
    }
    else {
        $CustomPath = $UserInput -replace '"', ''
        while (-not (Test-Path $CustomPath)) {
            Write-Error "Path does not exist: $CustomPath"
            $CustomPath = Read-Host " > Please enter a valid path"
            $CustomPath = $CustomPath -replace '"', ''
        }
        $WiresharkBaseDir = $CustomPath
        Write-Host "[LIBS] Custom path accepted: $WiresharkBaseDir" -ForegroundColor Green
    }
}

# ==========================================
# 0.2 QT PATH DETECTION
# ==========================================
$DefaultQtPath = "C:/dev/qt/6.9.3/msvc2022_64"
$QtPath = $null

if (Test-Path $DefaultQtPath) {
    Write-Host "[QT]   Found at default location: $DefaultQtPath" -ForegroundColor Green
    $QtPath = $DefaultQtPath
}
else {
    Write-Warning "[QT] Default path not found ($DefaultQtPath)"
    Write-Host "Please enter the absolute path to Qt 6 (msvc2022_64)." -ForegroundColor Yellow
    
    while ($true) {
        $QtInput = Read-Host " > Qt Path"
        $QtInput = $QtInput -replace '"', ''
        
        if (Test-Path $QtInput) {
            $QtPath = $QtInput
            Write-Host "[QT] Valid path accepted." -ForegroundColor Green
            break
        }
        else {
            Write-Error "Path does not exist. Please try again."
        }
    }
}

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
# 1. ENVIRONMENT CHECK
# ==========================================
if (-not (Get-Command "cl.exe" -ErrorAction SilentlyContinue)) {
    Write-Host " [ERROR] VISUAL STUDIO ENVIRONMENT NOT DETECTED" -ForegroundColor Red
    Write-Host " Please open 'x64 Native Tools Command Prompt'." -ForegroundColor Yellow
    exit 1
}

if ($env:VSCMD_ARG_TGT_ARCH -ne "x64") {
    $clOutput = & cl.exe 2>&1 | Out-String
    if ($clOutput -match "x86" -and $clOutput -notmatch "x64") {
        Write-Host " [ERROR] WRONG ARCHITECTURE DETECTED (x86)" -ForegroundColor Red
        Write-Host " Please open 'x64 Native Tools Command Prompt'." -ForegroundColor Yellow
        exit 1
    }
}

# ==========================================
# 2. SDK DETECTION
# ==========================================
$SdkPaths = @("C:\Program Files (x86)\Windows Kits\10\Include", "C:\Program Files\Windows Kits\10\Include")
$LatestSdkVersion = $null
foreach ($path in $SdkPaths) {
    if (Test-Path $path) {
        $Ver = Get-ChildItem -Path $path -Directory | Where-Object { $_.Name -like "10.*" } | Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty Name
        if ($Ver) { $LatestSdkVersion = $Ver; break }
    }
}
if ($LatestSdkVersion) {
    if (-not $LatestSdkVersion.EndsWith("\")) { $LatestSdkVersion = "$LatestSdkVersion\" }
    $env:WindowsSDKVersion = $LatestSdkVersion
    $env:WindowsSDKLibVersion = $LatestSdkVersion
}

# ==========================================
# 3. DETERMINE DESIRED STATE
# ==========================================
$IsNinja = $false
$DesiredGeneratorName = "Visual Studio" # Default internal name for logic
if ($Ninja) {
    if (Get-Command "ninja.exe" -ErrorAction SilentlyContinue) {
        $IsNinja = $true
        $DesiredGeneratorName = "Ninja"
        Write-Host "[SYSTEM] Target Generator: NINJA" -ForegroundColor Cyan
    }
    else {
        Write-Error "Ninja not found."
        exit 1
    }
}
else {
    Write-Host "[SYSTEM] Target Generator: VISUAL STUDIO" -ForegroundColor Cyan
}

$WErrorValue = "ON"
if ($AllowWarnings) { $WErrorValue = "OFF" }

# ==========================================
# 4. EXECUTION
# ==========================================
if ($Clean) {
    if (Test-Path $BuildPath) {
        Write-Host "Cleaning build directory..." -ForegroundColor Yellow
        Remove-Item -Path $BuildPath -Recurse -Force
    }
}

if (-not (Test-Path $BuildPath)) { New-Item -Path $BuildPath -ItemType Directory | Out-Null }
Push-Location $BuildPath

try {
    # ---------------------------------------------------------
    # SMART CMAKE LOGIC
    # ---------------------------------------------------------
    $RunCMake = $true
    $CacheFile = "CMakeCache.txt"

    if (Test-Path $CacheFile) {
        $CacheContent = Get-Content $CacheFile | Out-String
        
        # 1. Check Generator Match
        $CacheHasNinja = $CacheContent -match "CMAKE_GENERATOR:INTERNAL=Ninja"
        $CacheHasVS = $CacheContent -match "CMAKE_GENERATOR:INTERNAL=Visual Studio"
        
        $GeneratorMismatch = ($IsNinja -and -not $CacheHasNinja) -or (-not $IsNinja -and -not $CacheHasVS)
        
        # 2. Check WError Flag Match
        # Regex looks for ENABLE_WERROR:BOOL=ON or OFF
        $WErrorMismatch = $false
        if ($CacheContent -match "ENABLE_WERROR:BOOL=($WErrorValue)") {
            $WErrorMismatch = $false
        }
        else {
            # Only trigger mismatch if the key exists but value differs
            if ($CacheContent -match "ENABLE_WERROR:BOOL=") { $WErrorMismatch = $true }
        }

        if ($GeneratorMismatch) {
            Write-Warning "Generator changed. Wiping cache to switch..."
            Remove-Item $CacheFile -Force -ErrorAction SilentlyContinue
            if (Test-Path "CMakeFiles") { Remove-Item "CMakeFiles" -Recurse -Force -ErrorAction SilentlyContinue }
            $RunCMake = $true
        }
        elseif ($WErrorMismatch) {
            Write-Host "Build flags changed (Warnings). Re-configuring..." -ForegroundColor Yellow
            $RunCMake = $true
        }
        elseif ($ForceCMake) {
            Write-Host "Forced configuration requested." -ForegroundColor Yellow
            $RunCMake = $true
        }
        else {
            Write-Host "Build system is up to date. Skipping CMake." -ForegroundColor Green
            $RunCMake = $false
        }
    }

    # ---------------------------------------------------------
    # CMAKE CONFIGURATION
    # ---------------------------------------------------------
    if ($RunCMake) {
        Write-Host "Configuring CMake..." -ForegroundColor Green
        $Generator = "Visual Studio 18 2026"
        $Arch = "x64"
        if ($IsNinja) { $Generator = "Ninja" }

        $SdkArg = $LatestSdkVersion.TrimEnd("\")
        $CMakeArgs = @("-G", $Generator, "-DENABLE_WERROR=$WErrorValue", "-DCMAKE_RC_FLAGS='-DWIN32'", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON")

        if ($LatestSdkVersion) {
            $CMakeArgs += "-DCMAKE_SYSTEM_VERSION=$SdkArg"
            $CMakeArgs += "-DCMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION=$SdkArg"
        }

        if ($IsNinja) { $CMakeArgs += "-DCMAKE_BUILD_TYPE=RelWithDebInfo" } 
        else { $CMakeArgs += "-A", $Arch }

        $CMakeArgs += $SourceDir
        & cmake $CMakeArgs
        if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed." }
    }

    # ---------------------------------------------------------
    # BUILD
    # ---------------------------------------------------------
    Write-Host "Building project..." -ForegroundColor Green

    if ($IsNinja) {
        & ninja
    }
    else {
        & msbuild /m /p:Configuration=RelWithDebInfo Wireshark.sln
    }

    if ($LASTEXITCODE -ne 0) { throw "Build failed." }

    # ---------------------------------------------------------
    # INSTALLER
    # ---------------------------------------------------------
    if ($Installer) {
        Write-Host "Generating Installer..." -ForegroundColor Magenta
        & msbuild /m /p:Configuration=RelWithDebInfo wireshark_nsis_prep.vcxproj
        if ($LASTEXITCODE -eq 0) {
            & msbuild /m /p:Configuration=RelWithDebInfo wireshark_nsis.vcxproj
        }
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "=========================================" -ForegroundColor Green
            Write-Host " INSTALLER READY at build\packaging\nsis " -ForegroundColor Green
            Write-Host "=========================================" -ForegroundColor Green
        }
        else {
            Write-Warning "Failed to create installer (Check NSIS)."
        }
    }

    Write-Host "Build Process Completed." -ForegroundColor Green
}
catch {
    Write-Error $_
}
finally {
    Pop-Location
    Write-Host "[SYSTEM] Done." -ForegroundColor Gray
}