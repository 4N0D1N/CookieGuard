@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
set "PYTHONPATH=%~dp0"
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY where python >nul 2>&1 && set "PY=python"
if not defined PY (
  echo No encuentro Python. Instalalo para poder desinstalar con el asistente.
  pause
  exit /b 1
)
%PY% -m cookieguard desinstalar
echo.
pause
