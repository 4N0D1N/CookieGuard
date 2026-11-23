@echo off
chcp 65001 >nul
cd /d "%~dp0\.."
echo Iniciando CookieGuard en la bandeja del sistema...
start pythonw -m cookieguard tray
