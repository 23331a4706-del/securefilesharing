@echo off
title Stop Secure File Sharing System
echo Stopping all Secure File Sharing background services...

taskkill /FI "WINDOWTITLE eq 1. Hardhat Node (Blockchain)*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq 2. Flask Backend API*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq 3. Vite React Frontend*" /F >nul 2>&1

echo All application services have been stopped successfully.
pause
