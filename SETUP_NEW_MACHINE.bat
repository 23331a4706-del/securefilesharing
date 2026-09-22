@echo off
title Setup Secure File Sharing System on New Computer
echo =====================================================================
echo       SETTING UP SECURE FILE SHARING ON A NEW COMPUTER
echo =====================================================================
echo.

echo [1/3] Setting up Python Virtual Environment in backend...
cd /d "%~dp0backend"
if exist venv ( rmdir /s /q venv )
python -m venv venv
call .\venv\Scripts\activate.bat
pip install -r requirements.txt

echo.
echo [2/3] Installing Blockchain Node dependencies...
cd /d "%~dp0blockchain"
call npm install

echo.
echo [3/3] Installing Frontend Web dependencies...
cd /d "%~dp0frontend"
call npm install

echo.
echo =====================================================================
echo SETUP COMPLETE! 
echo Now double-click 'START_APP.bat' to launch the application!
echo =====================================================================
pause
