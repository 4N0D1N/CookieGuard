@echo off
chcp 65001 >nul
title CookieGuard - Sembrar Perfil Trampa (Honeypot)
cd /d "%~dp0.."
python -m cookieguard honeypot --setup
echo.
pause
