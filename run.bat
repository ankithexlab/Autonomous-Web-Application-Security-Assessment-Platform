@echo off
title Starting AWASAP Project...
echo ======================================================
echo           Starting AWASAP (Backend + Frontend)
echo ======================================================

:: 1. Start Backend in a separate window
start "AWASAP Backend" cmd /k "cd /d "%~dp0backend" && call .venv\Scripts\activate && uvicorn app.main:app --reload --port 8000"

:: 2. Wait 2 seconds for backend
timeout /t 2 /nobreak >nul

:: 3. Start Frontend in a separate window
start "AWASAP Frontend" cmd /k "cd /d "%~dp0" && npm run dev"

:: 4. Wait 3 seconds and automatically open in browser
timeout /t 3 /nobreak >nul
start http://localhost:5173

echo.
echo [DONE] Backend and Frontend started!
echo Browser opened at http://localhost:5173
exit
