@echo off
title CookieGuard - Armar Trampa Activa Canary
python -m cookieguard trap --deploy
python -m cookieguard trap --check
pause
