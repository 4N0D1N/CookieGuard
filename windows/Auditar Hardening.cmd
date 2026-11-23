@echo off
chcp 65001 >nul
cd /d "%~dp0\.."
echo ========================================================
echo  CookieGuard - Auditoria de Endurecimiento de Navegador
echo ========================================================
python -m cookieguard hardening
echo.
pause
