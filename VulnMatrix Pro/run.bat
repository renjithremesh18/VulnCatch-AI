@echo off
title VulnMatrix Pro
color 0B

:: Find Python
set PYTHON_EXE=

if exist "C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python312\python.exe" set PYTHON_EXE=C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python312\python.exe
if exist "C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python311\python.exe" set PYTHON_EXE=C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python311\python.exe
if exist "C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python310\python.exe" set PYTHON_EXE=C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python310\python.exe
if exist "C:\Python312\python.exe" set PYTHON_EXE=C:\Python312\python.exe
if exist "C:\Python311\python.exe" set PYTHON_EXE=C:\Python311\python.exe

if "%PYTHON_EXE%"=="" (
    where python.exe >nul 2>&1
    if %ERRORLEVEL%==0 (
        python.exe --version >nul 2>&1
        if %ERRORLEVEL%==0 set PYTHON_EXE=python.exe
    )
)

if "%PYTHON_EXE%"=="" (
    echo Python not found. Run setup_and_run.bat first.
    pause
    exit /b 1
)

echo.
echo  Starting VulnMatrix Pro...
echo  Open: http://localhost:5000
echo.
%PYTHON_EXE% app.py
pause
