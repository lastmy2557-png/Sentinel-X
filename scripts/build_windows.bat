@echo off
SETLOCAL EnableDelayedExpansion

REM ============================================================================
REM Sentinel-X — Windows Standalone Executable (.exe) One-Click Builder
REM Run this script on Windows to compile dist\sentinel-x.exe
REM ============================================================================

cd /d "%~dp0\.."
echo ============================================================================
echo [Sentinel-X] Starting Windows .exe Build Pipeline...
echo Workspace: %CD%
echo ============================================================================

REM 1. Verify Python 3.11+ is available
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python was not found in PATH. Please install Python 3.11+ from python.org.
    pause
    exit /b 1
)

python --version

REM 2. Create local virtual environment (.venv) if not present
if not exist ".venv\Scripts\python.exe" (
    echo [Sentinel-X] Creating local virtual environment (.venv)...
    python -m venv .venv
    if !ERRORLEVEL! NEQ 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
)

REM 3. Install PyInstaller and PyYAML inside .venv
echo [Sentinel-X] Installing build tools (pyinstaller, pyyaml) in .venv...
".venv\Scripts\python.exe" -m pip install --upgrade pip pyinstaller pyyaml
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to install PyInstaller / PyYAML.
    pause
    exit /b 1
)

REM 4. Run Unit & Integration Tests before building
echo [Sentinel-X] Running Automated Test Suite...
".venv\Scripts\python.exe" -m unittest discover -s tests -p "test_*.py" -v
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Automated tests failed. Aborting .exe build.
    pause
    exit /b 1
)

REM 5. Execute scripts/build_exe.py (runs Anti-REA Audit -> PyInstaller -> SHA-256 Manifest)
echo [Sentinel-X] Building dist\sentinel-x.exe...
".venv\Scripts\python.exe" scripts\build_exe.py
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Executable build failed.
    pause
    exit /b 1
)

echo.
echo ============================================================================
echo [SUCCESS] Build Completed Successfully!
echo   Executable : %CD%\dist\sentinel-x.exe
echo   SHA-256    : %CD%\dist\sentinel-x.exe.sha256
echo   Manifest   : %CD%\dist\build_manifest.json
echo ============================================================================
pause
exit /b 0
