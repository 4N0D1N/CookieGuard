@echo off
chcp 65001 >nul
title CookieGuard - Generar Dossier MITRE ATT&CK
cd /d "%~dp0.."
python -m cookieguard dossier --formato html
echo.
pause
