#!/usr/bin/env bash
# =====================================================================
#  QCG CLI - build script (macOS / Linux)
#
#  What it does:
#    1. Creates a clean Python virtual environment
#    2. Installs the QCG package + PyInstaller
#    3. Builds a standalone `qcg` binary (no Python needed to RUN it)
#    4. Assembles a ready-to-distribute "QCG-Employee" folder
#       (qcg + HELP.txt + COMMANDS.txt + config template)
#
#  How to run:
#    chmod +x build.sh
#    ./build.sh
#
#  Requires: Python 3.12+ (python3 --version should work)
#
#  NOTE: PyInstaller builds for the OS it runs on. Run this ON macOS to
#  get a macOS binary, and ON Linux to get a Linux binary. (Use BUILD.ps1
#  on Windows for the .exe.)
# =====================================================================
set -euo pipefail
cd "$(dirname "$0")"

echo ""
echo "=== QCG CLI build starting ==="
echo ""

# --- 0. sanity: python present? --------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 not found. Install Python 3.12+ and re-run." >&2
    exit 1
fi
echo "Found $(python3 --version)"

# --- 1. clean venv ---------------------------------------------------
echo ""
echo "[1/4] Creating virtual environment..."
rm -rf .venv
python3 -m venv .venv
PY="./.venv/bin/python"

# --- 2. install package + pyinstaller --------------------------------
echo ""
echo "[2/4] Installing QCG + PyInstaller (this can take a minute)..."
"$PY" -m pip install --upgrade pip --quiet
"$PY" -m pip install ./source --quiet
"$PY" -m pip install pyinstaller --quiet

# --- 3. build the binary ---------------------------------------------
echo ""
echo "[3/4] Building qcg binary..."
rm -rf build dist
"$PY" -m PyInstaller --onefile --name qcg \
    --paths source/src \
    --collect-submodules qcg_kms \
    --collect-submodules cryptography \
    --collect-submodules kyber_py \
    --collect-submodules dilithium_py \
    source/packaging/qcg_entry.py

if [ ! -f "dist/qcg" ]; then
    echo "ERROR: build failed - dist/qcg not found." >&2
    exit 1
fi

# --- 4. assemble employee bundle -------------------------------------
echo ""
echo "[4/4] Assembling employee bundle..."
BUNDLE="QCG-Employee"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE"
cp "dist/qcg" "$BUNDLE/qcg"
chmod +x "$BUNDLE/qcg"
cp "docs/START-HERE.txt" "$BUNDLE/START-HERE.txt"
cp "docs/HELP.txt" "$BUNDLE/HELP.txt"
cp "docs/COMMANDS.txt" "$BUNDLE/COMMANDS.txt"
cp "docs/config.example.json" "$BUNDLE/config.example.json"

echo ""
echo "=== DONE ==="
echo "Your binary:        $(pwd)/dist/qcg"
echo "Employee bundle:    $(pwd)/$BUNDLE/"
echo ""
echo "To distribute: zip/tar the '$BUNDLE' folder and send it."
echo "Each user follows HELP.txt to set their config and run qcg."
echo ""
