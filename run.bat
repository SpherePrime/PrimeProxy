@echo off
setlocal enabledelayedexpansion
title PrimeProxy Launcher
chcp 65001 >nul 2>&1

rem ============================================================
rem  PrimeProxy - batch launcher for the GUI app
rem  Checks Python and required libraries, installs what's
rem  missing, then starts the application.
rem ============================================================

cd /d "%~dp0"

echo.
echo   ============================================
echo     PrimeProxy - launcher
echo   ============================================
echo.

rem ---------- 1. Find a working Python ----------
set "PYEXE="
set "PYVER="
for %%P in (python py) do (
    if not defined PYEXE (
        where %%P >nul 2>&1
        if not errorlevel 1 (
            for /f "delims=" %%L in ('%%P --version 2^>^&1') do (
                if not defined PYVER set "PYVER=%%L"
            )
            if defined PYVER set "PYEXE=%%P"
        )
    )
)
if not defined PYEXE (
    echo   [ERROR] Python not found.
    echo           Install Python 3.9+ from https://www.python.org/downloads/
    echo           Check the "Add Python to PATH" option during install.
    pause
    exit /b 1
)
for /f "tokens=1,2 delims=. " %%A in ("!PYVER!") do set "PYMAJOR=%%B"
for /f "tokens=2,3 delims=. " %%A in ("!PYVER!") do set "PYMINOR=%%B"
if not defined PYMINOR set "PYMINOR=0"
echo   Python found: !PYVER!
if !PYMAJOR! LSS 3 goto PYOLD
if !PYMAJOR! EQU 3 if !PYMINOR! LSS 9 goto PYOLD
goto PYOK
:PYOLD
echo   [ERROR] Python 3.9+ is required, found !PYVER!
pause
exit /b 1
:PYOK

rem ---------- 2. Check required libraries ----------
set "MISSING="
%PYEXE% -c "import webview" 2>nul || set "MISSING=!MISSING! pywebview"
%PYEXE% -c "import pystray" 2>nul || set "MISSING=!MISSING! pystray"
%PYEXE% -c "import PIL" 2>nul || set "MISSING=!MISSING! Pillow"
%PYEXE% -c "import pyperclip" 2>nul || set "MISSING=!MISSING! pyperclip"
%PYEXE% -c "import certifi" 2>nul || set "MISSING=!MISSING! certifi"
%PYEXE% -c "import psutil" 2>nul || set "MISSING=!MISSING! psutil"
%PYEXE% -c "import cryptography" 2>nul || set "MISSING=!MISSING! cryptography"

if defined MISSING (
    echo   Missing dependencies:!MISSING!
    echo   Installing...
    %PYEXE% -m pip install --upgrade pip >nul 2>&1
    %PYEXE% -m pip install !MISSING!
    if errorlevel 1 (
        echo.
        echo   [ERROR] Failed to install dependencies.
        echo           Try: %PYEXE% -m pip install pywebview pystray Pillow pyperclip certifi psutil cryptography
        pause
        exit /b 1
    )
    echo   Dependencies installed.
)

rem ---------- 3. Launch ----------
echo.
echo   Starting PrimeProxy...
echo   Close this window: app keeps running in the system tray.
echo.
start "PrimeProxy" /min %PYEXE% main.py

endlocal