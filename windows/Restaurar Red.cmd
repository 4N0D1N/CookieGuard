@echo off
chcp 65001 >nul
title CookieGuard - Restaurar Red
echo [CookieGuard] Desactivando Killswitch de red...
cd /d "%~dp0\.."
py -3 -m cookieguard killswitch --desactivar || python -m cookieguard killswitch --desactivar
echo.
pause
