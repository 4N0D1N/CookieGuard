@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
title CookieGuard - Modo Rescate USB

echo ======================================================================
echo   🚨 COOKIEGUARD - PROTOCOLO DE RESCATE Y TRIAGE FORENSE USB 🚨
echo ======================================================================
echo.
echo Ejecutando desde soporte extraíble (USB): %~dp0
echo Configurando entorno seguro (no se alterará el disco del sistema)...
echo.

set "RESCUE_DIR=%~dp0Informes_Rescate_%COMPUTERNAME%"
if not exist "%RESCUE_DIR%" mkdir "%RESCUE_DIR%"
set "COOKIEGUARD_HOME=%RESCUE_DIR%"

if exist "%~dp0CookieGuard.exe" (
    echo [OK] Ejecutando binario standalone CookieGuard.exe...
    "%~dp0CookieGuard.exe" triage --salida "%RESCUE_DIR%"
) else (
    echo [INFO] Buscando entorno Python en el equipo o en el USB...
    python -m cookieguard triage --salida "%RESCUE_DIR%" 2>nul || py -3 -m cookieguard triage --salida "%RESCUE_DIR%" 2>nul
)

echo.
echo ======================================================================
echo Rescate completado con éxito.
echo Informes y checklist guardados en:
echo %RESCUE_DIR%
echo.
echo Abre "Informe_Rescate.html" para ver las sesiones abiertas.
echo Lee "URGENTE_ROTAR_CLAVES.txt" para saber que contraseñas cambiar primero.
echo ======================================================================
echo.
pause
