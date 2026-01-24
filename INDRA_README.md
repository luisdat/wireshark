# Wireshark Build Instructions (Windows x64)

This document outlines the software requirements, environment setup, and steps required to build Wireshark and generate the NSIS installer on Windows using the automated build script provided in this repository.

---

## 1. Software Requirements & Installation

You will need the following tools installed on your machine. Open **PowerShell** as Administrator to run the `winget` commands.

### A. Code Editor (Optional)
Recommended for editing code and scripts.
```powershell
winget install Microsoft.VisualStudioCode
```

### B. Visual Studio 2022 (Compiler)

**Crucial:** You need the MSVC compiler and the Windows 11 SDK.

1. Download **Visual Studio 2022** (Community) from [visualstudio.microsoft.com](https://visualstudio.microsoft.com).
2. During installation, select the **"Desktop development with C++"** workload.
3. Ensure the following **Individual Components** are checked on the right side:
* **Windows 11 SDK** (e.g., 10.0.22621.0 or higher). *Mandatory for C11 support.*
* **MSVC v143 - VS 2022 C++ x64/x86 build tools**.
* **C++ CMake tools for Windows**.



### C. Build Tools & Dependencies

Install Git, CMake, and the NSIS installer generator.

```powershell
winget install Git.Git
winget install Kitware.CMake
winget install NSIS.NSIS           # Required to generate the .exe installer
winget install Ninja-build.Ninja   # Optional: Faster compilation but harder to configure

```

### D. Qt 6 Framework

Wireshark requires the Qt6 libraries. This cannot be installed via winget easily.

You can download the usual QT or an easy-to-install package

Option A (the quicker)
```
curl.exe -LOJ https://github.com/miurahr/aqtinstall/releases/download/v3.3.0/aqt_x64.exe
.\aqt_x64.exe install-qt windows desktop 6.9.3 win64_msvc2022_64 -m qt5compat debug_info qtmultimedia
```
Option B (the official one)
1. **Download:** Go to the [Qt Online Installer](https://www.qt.io/download-open-source) (Open Source version).
2. **Install:** Run the installer. You will need a free Qt account.
3. **Select Components:**
* Expand **Qt 6.x** (e.g., 6.9.3 or the latest stable version).
* Check **MSVC 2022 64-bit**.


4. **Note the installation path.** The default is usually `C:\Qt`.

---

## 2. Configuration

### Qt Path
The build script (`build_wireshark.ps1`) automatically looks for Qt at:
`C:\dev\qt\6.9.3\msvc2022_64`

**If you have installed Qt elsewhere:**
You do **not** need to edit the script. When you run it, if the default path is not found, the script will pause and ask you to enter your specific Qt location in the console.

---

## 3. How to Build

You can use a PowerShell script (`build_wireshark.ps1`) that handles CMake configuration, Visual Studio patching, and architecture checks automatically.

### Step 1: Open the Build Environment

> [!IMPORTANT]
> **Do NOT use a standard PowerShell or CMD terminal.** You must use the **Visual Studio Developer Command Prompt**.

1. Press the **Windows Key**.
2. Type **x64 Native Tools Command Prompt for VS 2022** and open it.
3. Inside the black console window, type:
```cmd
powershell
```


*(This switches to PowerShell mode while keeping the required compilation environment variables).*

### Step 2: Run the Script

Navigate to the repository folder and execute the script.

```powershell
# 1. Go to your repo (adjust path as needed)
cd C:\dev\wireshark

# 2. Run the build script
.\build_wireshark.ps1 -VS -AllowWarnings

```

**Script Parameters:**

* `-VS`: Uses the Visual Studio MSBuild engine (Recommended for stability).
* `-Ninja`: Uses the Ninja engine (Faster but less compatible).
* `-AllowWarnings`: Prevents the build from stopping on non-critical code warnings.
* `-Installer`: Generates the final installer `.exe` setup file after compilation.
* `-Clean`: (Optional) Deletes the build folder to start from scratch.

---

## 4. Build Output

The script creates a `build` directory inside the repository.

* **Wireshark Executable:** You can run the compiled version directly from:
`.\build\run\RelWithDebInfo\Wireshark.exe`
* **Installer (.exe):** If the `-Installer` step succeeds, your setup file will be located at:
`.\build\packaging\nsis\Wireshark-win64-4.x.x.exe`

---

## 5. Troubleshooting

* **Error: "cl.exe not found":** You are not running inside the *x64 Native Tools Command Prompt*. See Step 1.
* **Error: "RC1212" or "SDK mismatch":** The script automatically fixes these by detecting the installed Windows SDK and applying specific flags to CMake. Ensure you have the Windows 11 SDK installed in Visual Studio Installer.
* **Linker Errors (wmem/heuristics):** If you modified dissectors, ensure you replaced `wmem_packet_scope()` with `pinfo->pool` and updated heuristic function signatures to match Wireshark 4.x API.
