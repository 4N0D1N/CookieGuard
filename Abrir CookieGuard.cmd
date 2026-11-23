@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
cd /d "%~dp0"
set "PYTHONPATH=%~dp0"

set "PYW="
where pyw >nul 2>&1 && set "PYW=pyw -3"
if not defined PYW where pythonw >nul 2>&1 && set "PYW=pythonw"
if not defined PYW where py >nul 2>&1 && set "PYW=py -3"
if not defined PYW where python >nul 2>&1 && set "PYW=python"

if not defined PYW (
    for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
        if exist "%%D\pythonw.exe" set "PYW=%%D\pythonw.exe"
        if not defined PYW if exist "%%D\python.exe" set "PYW=%%D\python.exe"
    )
)
if not defined PYW (
    for /d %%D in ("%ProgramFiles%\Python3*") do (
        if exist "%%D\pythonw.exe" set "PYW=%%D\pythonw.exe"
        if not defined PYW if exist "%%D\python.exe" set "PYW=%%D\python.exe"
    )
)
if not defined PYW (
    if exist "%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe" set "PYW=%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe"
)

if not defined PYW (
    echo ============================================================
    echo  No se encontro Python en el sistema.
    echo  Para usar CookieGuard, instala Python 3.8 o superior con:
    echo    winget install Python.Python.3.12
    echo  o descargalo desde https://www.python.org/downloads/
    echo ============================================================
    pause
    exit /b 1
)

start "" %PYW% -m cookieguard gui
exit /b 0
