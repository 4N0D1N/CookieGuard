@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
set "PYTHONPATH=%~dp0"
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY where python >nul 2>&1 && set "PY=python"
if not defined PY (
  echo CookieGuard necesita Python 3.8 o superior y no lo encuentro.
  echo Instalalo con:  winget install Python.Python.3.12
  echo o desde https://www.python.org/downloads/windows/  ^(marca "Add python.exe to PATH"^)
  pause
  exit /b 1
)
echo ============================================================
echo  Instalacion de CookieGuard
echo  Se te preguntara antes de cada cambio en el sistema.
echo ============================================================
%PY% -m cookieguard instalar
echo.
pause
