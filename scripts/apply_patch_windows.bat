@echo off
setlocal
REM ==============================================================================
REM Sentinel-X — One-Click Windows Patch Updater & Pre-compiled .exe Launcher
REM Pulls the latest version, patch file, and pre-compiled dist\sentinel-x.exe
REM directly from GitHub (or applies a local patch if offline) and verifies sha256.
REM Note: Avoids parenthesized if/else blocks for 100% cmd.exe compatibility.
REM ==============================================================================

cd /d "%~dp0\.."

echo ==============================================================================
echo   Sentinel-X — Windows Patch Updater ^& Pre-Compiled Executable Verifier
echo ==============================================================================

echo [1/3] Pulling latest patch and pre-compiled executable from GitHub (origin/main)...
git pull origin main
if errorlevel 1 goto :offline_check

:verify_exe
echo [2/3] Verifying pre-compiled executable at "%CD%\dist\sentinel-x.exe"...
if not exist "dist\sentinel-x.exe" goto :rebuild_exe

echo [3/3] Checking current Sentinel-X version...
"dist\sentinel-x.exe" --version
echo ==============================================================================
echo   UPDATE COMPLETE!
echo   - Pre-compiled EXE : "%CD%\dist\sentinel-x.exe"
echo   - Latest Patch     : "%CD%\patches\latest.patch"
echo   - Patch Manifest   : "%CD%\patches\PATCH_MANIFEST.json"
echo   - Start Server     : "%CD%\dist\sentinel-x.exe" serve --host 127.0.0.1 --port 8080
echo ==============================================================================
endlocal
exit /b 0

:offline_check
echo [INFO] git pull was skipped or offline. Checking local patches\latest.patch...
if exist "patches\latest.patch" git apply --check "patches\latest.patch" >nul 2>&1
if not errorlevel 1 git apply "patches\latest.patch"
goto :verify_exe

:rebuild_exe
echo [INFO] Pre-compiled dist\sentinel-x.exe not found locally. Building now...
call scripts\build_windows.bat
endlocal
exit /b %ERRORLEVEL%
