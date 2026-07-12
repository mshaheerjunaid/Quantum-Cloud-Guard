========================================================================
  QCG CLI BUILD KIT  (for the administrator)
========================================================================

This kit builds the standalone qcg program and assembles the bundle you
hand out. The qcg program runs with NO Python needed.

IMPORTANT: the build tool (PyInstaller) builds for the OS it runs on.
You cannot cross-build. So:
  - Build the Windows .exe   by running BUILD.ps1   ON Windows
  - Build the macOS binary   by running build.sh    ON a Mac
  - Build the Linux binary   by running build.sh    ON Linux
The CLI source is identical; only run the matching builder per OS.

------------------------------------------------------------------------
  WHAT'S INSIDE
------------------------------------------------------------------------
  BUILD.ps1                 <- one-click builder for WINDOWS (.exe)
  build.sh                  <- builder for macOS / LINUX
  source/                   <- the QCG package source (the CLI lives here)
  docs/                     <- user docs that go into the bundle
      HELP.txt
      COMMANDS.txt
      config.example.json
  README.txt                <- this file

------------------------------------------------------------------------
  HOW TO BUILD - WINDOWS (.exe)
------------------------------------------------------------------------
  1. Install Python 3.12+ (python.org, tick "Add to PATH").
  2. In PowerShell:
         cd "C:\path\to\QCG-CLI-Kit"
         Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
         .\BUILD.ps1
  3. Output:
         dist\qcg.exe          <- the standalone executable
         QCG-Employee\         <- ready-to-distribute folder

------------------------------------------------------------------------
  HOW TO BUILD - macOS / LINUX
------------------------------------------------------------------------
  1. Make sure python3 --version works (Python 3.12+).
  2. In Terminal:
         cd /path/to/QCG-CLI-Kit
         chmod +x build.sh
         ./build.sh
  3. Output:
         dist/qcg              <- the standalone binary
         QCG-Employee/         <- ready-to-distribute folder

------------------------------------------------------------------------
  DISTRIBUTING
------------------------------------------------------------------------
  - Zip (Windows) or tar (mac/Linux) the QCG-Employee folder and send it.
  - Give each user their own API key (create it in the web console under
    "API Keys") and their key name(s).
  - They follow HELP.txt to set their config and run qcg.

  NOTE: send users the build for THEIR OS. A Windows .exe won't run on a
  Mac and vice-versa. Build on each OS you need to support.

------------------------------------------------------------------------
  TEST IT YOURSELF FIRST
------------------------------------------------------------------------
  Write your own config (use one of YOUR api keys), then round-trip:

     Windows:
        .\dist\qcg.exe encrypt "C:\path\to\test.pdf" --key your-key --bench
        .\dist\qcg.exe decrypt "C:\path\to\test.pdf.qcg" --bench

     macOS / Linux:
        ./dist/qcg encrypt ~/test.pdf --key your-key --bench
        ./dist/qcg decrypt ~/test.pdf.qcg --bench

  The --bench flag prints encryption/decryption timing plus your machine
  specs (CPU model, cores/threads, speed, RAM size/speed, GPU).
