@echo off
title Secure File Sharing System Launcher
echo =====================================================================
echo           SECURE FILE SHARING USING AES & BLOCKCHAIN
echo                    One-Click Application Launcher
echo =====================================================================
echo.

echo [1/4] Starting Local Hardhat Blockchain Node...
start "1. Hardhat Node (Blockchain)" /min cmd /c "cd /d "%~dp0blockchain" && npx hardhat node"

echo [2/4] Deploying Smart Contract to Local Blockchain...
timeout /t 5 /nobreak >nul
cd /d "%~dp0blockchain"
call npx hardhat run scripts/deploy.js --network localhost

echo.
echo [3/4] Starting Flask Python Backend API...
start "2. Flask Backend API" /min cmd /c "cd /d "%~dp0backend" && .\venv\Scripts\python.exe run.py"

echo [4/4] Starting React + Vite Web Frontend...
start "3. Vite React Frontend" /min cmd /c "cd /d "%~dp0frontend" && npm run dev"

echo.
echo =====================================================================
echo SUCCESS! All services have been launched in the background.
echo.
echo Access URL (Local Machine):  http://localhost:3000
echo Access URL (Network Link):   http://127.0.0.1:3000
echo =====================================================================
echo Opening browser in 3 seconds...
timeout /t 3 /nobreak >nul
start http://localhost:3000
exit
