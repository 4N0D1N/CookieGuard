@echo off
chcp 65001 >nul
title CookieGuard - Revocación Rápida de Sesiones
cd /d "%~dp0.."
python -m cookieguard revocar
echo.
pause
