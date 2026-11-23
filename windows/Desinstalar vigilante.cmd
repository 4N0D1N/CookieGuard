@echo off
chcp 65001 >nul
echo [CookieGuard] Desinstalando vigilante de Windows...
cd /d "%~dp0\.."
python -m cookieguard.installer --desinstalar
pause
