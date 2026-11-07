@echo off
REM ============================================================================
REM Sentinel-X — Windows Standalone Executable (.exe) One-Click Builder
REM Uses flat goto labels (no parenthesized blocks) to prevent cmd.exe parsing errors
REM ============================================================================

cd /d "%~dp0\.."
echo ============================================================================
echo [Sentinel-X] Starting Windows .exe Build Pipeline
echo Workspace: %CD%
echo ============================================================================

REM 1. Verify Python is available
where python >nul 2>nul
if errorlevel 1 goto :no_python

python --version

REM 2. Create local virtual environment in .venv if not present
if exist ".venv\Scripts\python.exe" goto :venv_ready
echo [Sentinel-X] Creating local virtual environment in .venv ...
python -m venv .venv
if errorlevel 1 goto :venv_fail

:venv_ready
REM 3. Install PyInstaller and PyYAML inside .venv (non-fatal if Python 3.14 lacks prebuilt wheels)
echo [Sentinel-X] Installing build tools in .venv ...
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install pyinstaller pyyaml
if errorlevel 1 echo [Sentinel-X] Note: PyInstaller/PyYAML wheel not available for this Python version; built-in fallback will be used.

REM 4. Run Unit and Integration Tests before building
echo [Sentinel-X] Running Automated Test Suite ...
".venv\Scripts\python.exe" -m unittest discover -s tests -p "test_*.py" -v
if errorlevel 1 goto :test_fail

REM 5. Execute scripts\build_exe.py (runs Anti-REA Audit -> Builds .exe -> SHA-256 Manifest)
echo [Sentinel-X] Building dist\sentinel-x.exe ...
".venv\Scripts\python.exe" scripts\build_exe.py
if errorlevel 1 goto :build_fail

echo.
echo ============================================================================
echo [SUCCESS] Build Completed Successfully!
echo   Executable : %CD%\dist\sentinel-x.exe
echo   SHA-256    : %CD%\dist\sentinel-x.exe.sha256
echo   Manifest   : %CD%\dist\build_manifest.json
echo ============================================================================
pause
exit /b 0

:no_python
echo [ERROR] Python was not found in PATH. Please install Python 3.11+ from python.org.
pause
exit /b 1

:venv_fail
echo [ERROR] Failed to create virtual environment in .venv.
pause
exit /b 1

:test_fail
echo [ERROR] Automated tests failed. Aborting .exe build.
pause
exit /b 1

:build_fail
echo [ERROR] Executable build failed.
pause
exit /b 1
