@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
cd /d "%~dp0"
set "PYTHONPATH=%~dp0"

set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY where python >nul 2>&1 && set "PY=python"

if not defined PY (
    for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
        if exist "%%D\python.exe" set "PY=%%D\python.exe"
    )
)
if not defined PY (
    for /d %%D in ("%ProgramFiles%\Python3*") do (
        if exist "%%D\python.exe" set "PY=%%D\python.exe"
    )
)
if not defined PY (
    if exist "%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe" set "PY=%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe"
)

if not defined PY (
    echo ============================================================
    echo  No se encontro Python en el sistema.
    echo  Instala Python con:
    echo    winget install Python.Python.3.12
    echo ============================================================
    pause
    exit /b 1
)

echo ============================================================
echo  CookieGuard - Auditor de Cookies de Sesion
echo  Analizando perfiles y buscando indicios de exfiltracion...
echo ============================================================
%PY% -m cookieguard analizar
echo.
pause
