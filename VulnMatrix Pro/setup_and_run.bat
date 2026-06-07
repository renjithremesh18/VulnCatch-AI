@echo off
title VulnMatrix Pro — Setup
color 0B
cls
echo.
echo  =================================================
echo    VulnMatrix Pro - First Time Setup
echo  =================================================
echo.

:: Check for Python in common locations
set PYTHON_EXE=

:: Check user-installed Python
if exist "C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python312\python.exe" (
    set PYTHON_EXE=C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python312\python.exe
    goto :found
)
if exist "C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python311\python.exe" (
    set PYTHON_EXE=C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python311\python.exe
    goto :found
)
if exist "C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python310\python.exe" (
    set PYTHON_EXE=C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python310\python.exe
    goto :found
)
:: Check system-wide Python
if exist "C:\Python312\python.exe" (
    set PYTHON_EXE=C:\Python312\python.exe
    goto :found
)
if exist "C:\Python311\python.exe" (
    set PYTHON_EXE=C:\Python311\python.exe
    goto :found
)
:: Check PATH
where python.exe >nul 2>&1
if %ERRORLEVEL%==0 (
    set PYTHON_EXE=python.exe
    :: But verify it is not just a stub
    python.exe --version >nul 2>&1
    if %ERRORLEVEL%==0 goto :found
)

echo  [!] Python 3 is NOT installed on this system.
echo.
echo  Please install Python 3.10 or newer from:
echo    https://www.python.org/downloads/
echo.
echo  IMPORTANT: During install, check the box:
echo    "Add Python to PATH"
echo.
echo  After installing Python, run this file again.
echo.
pause
exit /b 1

:found
echo  [OK] Found Python at: %PYTHON_EXE%
%PYTHON_EXE% --version
echo.
echo  Installing required packages...
echo.
%PYTHON_EXE% -m pip install --upgrade pip
%PYTHON_EXE% -m pip install flask python-nmap requests dnspython python-whois urllib3

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo  [!] Package installation failed. Please check your internet connection.
    pause
    exit /b 1
)

echo.
echo  =================================================
echo   All packages installed successfully!
echo  =================================================
echo.
echo  NOTE: Nmap must also be installed for port scanning:
echo    https://nmap.org/download.html
echo.
echo  Starting VulnMatrix Pro...
echo.
echo  Open your browser and go to: http://localhost:5000
echo.
%PYTHON_EXE% app.py
pause
