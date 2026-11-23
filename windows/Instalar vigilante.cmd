@echo off
chcp 65001 >nul
echo [CookieGuard] Instalando vigilante en segundo plano...
cd /d "%~dp0\.."
python -m cookieguard.installer --instalar-vigilante
pause
