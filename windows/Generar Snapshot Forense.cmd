@echo off
chcp 65001 >nul
title CookieGuard - Captura de Snapshot Forense
cd /d "%~dp0.."
python -m cookieguard snapshot
echo.
pause
