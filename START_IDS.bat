@echo off
:: ================================================================
::  Real-Time ML-Enhanced IDS — One-Click Launcher (with auto-install)
::  Author: Vamshi Krishna | Fall 2025
::  Just double-click this file → everything works!
:: ================================================================

cd /

echo.
echo ========================================================
echo   Real-Time ML-Enhanced IDS — Starting in 3... 2... 1...
echo ========================================================
echo.

:: Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found! Please install Python 3.11+ from python.org
    pause
    exit /b 1
)

:: Check if requirements.txt exists
if not exist requirements.txt (
    echo ERROR: requirements.txt not found!
    pause
    exit /b 1
)

:: Create/activate virtual environment (optional but cleaner)
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

echo.
echo Activating virtual environment...
call venv\Scripts\activate.bat

:: Upgrade pip first (quietly)
echo.
echo Upgrading pip...
python -m pip install --upgrade pip --quiet

:: Install all requirements (only if not already installed)
echo.
echo Installing / updating all dependencies (this may take 1-2 minutes first time)...
pip install -r requirements.txt --quiet

:: Final success message
echo.
echo SUCCESS! All dependencies installed.
echo.
echo Starting FastAPI backend[](http://localhost:8000)...
start "IDS Backend" python -m uvicorn app.api:app --host 0.0.0.0 --port 8000 --reload

echo.
echo Waiting 6 seconds for backend to start...
timeout /t 6 >nul

echo Starting Streamlit dashboard[](http://localhost:8502)...
start "IDS Dashboard" python -m streamlit run app/streamlit_app.py --server.port 8502 --server.address 0.0.0.0

:: Auto-open browser tabs (optional — comment out if you don't want)
timeout /t 8 >nul
start http://localhost:8502
start http://localhost:8000/docs

echo.
echo SUCCESS! SYSTEM IS NOW RUNNING!
echo.
echo Backend API   → http://localhost:8000/docs
echo Dashboard     → http://localhost:8502
echo.
echo Close this window (or press any key) to stop both servers.
echo.
pause