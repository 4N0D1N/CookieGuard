@echo off
chcp 65001 >nul
title CookieGuard - Aislamiento de Red de Emergencia
echo [CookieGuard] Activando Killswitch de red (bloqueo de trafico saliente)...
cd /d "%~dp0\.."
py -3 -m cookieguard killswitch --activar || python -m cookieguard killswitch --activar
echo.
pause
