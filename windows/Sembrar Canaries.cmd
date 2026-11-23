@echo off
chcp 65001 >nul
title CookieGuard - Sembrado de Cebos Canary
echo [CookieGuard] Sembrando cookies trampa en todos los perfiles de navegador...
cd /d "%~dp0\.."
py -3 -m cookieguard canary --plantar || python -m cookieguard canary --plantar
echo.
pause
