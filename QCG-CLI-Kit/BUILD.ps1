# =====================================================================
#  QCG CLI - one-click build script (Windows PowerShell)
#
#  What it does:
#    1. Creates a clean Python virtual environment
#    2. Installs the QCG package + PyInstaller
#    3. Builds a standalone qcg.exe (no Python needed to RUN it)
#    4. Assembles a ready-to-distribute "QCG-Employee" folder
#       (qcg.exe + HELP.txt + COMMANDS.txt + config template)
#
#  How to run:
#    Right-click this file > "Run with PowerShell"
#    OR open PowerShell in this folder and run:  .\BUILD.ps1
#
#  Requires: Python 3.12+ installed and on PATH (python --version should work)
# =====================================================================

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host ""
Write-Host "=== QCG CLI build starting ===" -ForegroundColor Cyan
Write-Host ""

# --- 0. sanity: is Python available? ---------------------------------
try {
    $pyver = (python --version) 2>&1
    Write-Host "Found $pyver" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Python not found on PATH." -ForegroundColor Red
    Write-Host "Install Python 3.12+ from python.org (tick 'Add to PATH'), then re-run." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# --- 1. clean venv ---------------------------------------------------
Write-Host ""
Write-Host "[1/4] Creating virtual environment..." -ForegroundColor Cyan
if (Test-Path ".venv") { Remove-Item ".venv" -Recurse -Force }
python -m venv .venv
$py = ".\.venv\Scripts\python.exe"

# --- 2. install package + pyinstaller --------------------------------
Write-Host ""
Write-Host "[2/4] Installing QCG + PyInstaller (this can take a minute)..." -ForegroundColor Cyan
& $py -m pip install --upgrade pip --quiet
& $py -m pip install ".\source" --quiet
& $py -m pip install pyinstaller --quiet

# --- 3. build the exe ------------------------------------------------
Write-Host ""
Write-Host "[3/4] Building qcg.exe..." -ForegroundColor Cyan
if (Test-Path "build") { Remove-Item "build" -Recurse -Force }
if (Test-Path "dist")  { Remove-Item "dist"  -Recurse -Force }
& $py -m PyInstaller --onefile --name qcg `
    --paths source\src `
    --collect-submodules qcg_kms `
    --collect-submodules cryptography `
    --collect-submodules kyber_py `
    --collect-submodules dilithium_py `
    source\packaging\qcg_entry.py

if (-not (Test-Path "dist\qcg.exe")) {
    Write-Host "ERROR: build failed - dist\qcg.exe not found." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# --- 4. assemble employee bundle -------------------------------------
Write-Host ""
Write-Host "[4/4] Assembling employee bundle..." -ForegroundColor Cyan
$bundle = "QCG-Employee"
if (Test-Path $bundle) { Remove-Item $bundle -Recurse -Force }
New-Item -ItemType Directory -Path $bundle | Out-Null
Copy-Item "dist\qcg.exe" "$bundle\qcg.exe"
Copy-Item "docs\START-HERE.txt" "$bundle\START-HERE.txt"
Copy-Item "docs\HELP.txt" "$bundle\HELP.txt"
Copy-Item "docs\COMMANDS.txt" "$bundle\COMMANDS.txt"
Copy-Item "docs\config.example.json" "$bundle\config.example.json"

Write-Host ""
Write-Host "=== DONE ===" -ForegroundColor Green
Write-Host "Your exe:            $PSScriptRoot\dist\qcg.exe" -ForegroundColor Green
Write-Host "Employee bundle:     $PSScriptRoot\$bundle\" -ForegroundColor Green
Write-Host ""
Write-Host "To distribute to employees: zip the '$bundle' folder and send it." -ForegroundColor Yellow
Write-Host "Each employee follows START-HERE.txt to set their key and run qcg." -ForegroundColor Yellow
Write-Host ""
Read-Host "Press Enter to exit"
