@echo off
setlocal enabledelayedexpansion

echo ========================================
echo   FortiGate Audit Application Launcher
echo ========================================
echo.

REM Check if Python is available
where py >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.8+
    pause
    exit /b 1
)

REM Check if Node.js is available
where node >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js not found. Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

echo [1/4] Setting up backend...
cd /d "%~dp0backend"

REM Setup backend virtual environment
if not exist ".venv" (
    echo     Creating Python virtual environment...
    py -m venv .venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
)

REM Activate and install backend dependencies
call .venv\Scripts\activate.bat
if not exist ".venv\Lib\site-packages\fastapi" (
    echo     Installing backend dependencies...
    pip install -q -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install backend dependencies
        pause
        exit /b 1
    )
)

echo [2/4] Setting up frontend...
cd /d "%~dp0frontend"

REM Install frontend dependencies
if not exist "node_modules" (
    echo     Installing frontend dependencies...
    call npm install --silent
    if errorlevel 1 (
        echo ERROR: Failed to install frontend dependencies
        pause
        exit /b 1
    )
)

echo [3/4] Starting backend server...
cd /d "%~dp0backend"
start "FortiGate Backend" /MIN cmd /k "cd /d %~dp0backend && echo Backend Server Running... && echo API: http://localhost:8000 && echo Docs: http://localhost:8000/docs && echo Press Ctrl+C to stop && echo. && .venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"

REM Wait for backend to start
timeout /t 3 /nobreak >nul

echo [4/4] Starting frontend server...
cd /d "%~dp0frontend"
start "FortiGate Frontend" /MIN cmd /k "cd /d %~dp0frontend && echo Frontend Server Running... && echo URL: http://localhost:5173 && echo Press Ctrl+C to stop && echo. && npm run dev"

echo.
echo ========================================
echo   Both servers are starting!
echo ========================================
echo.
echo Backend:  http://localhost:8000
echo          http://localhost:8000/docs (API docs)
echo.
echo Frontend: http://localhost:5173
echo.
echo Both servers are running in minimized windows.
echo Close those windows or press Ctrl+C in each to stop.
echo.
echo Opening application in browser...
timeout /t 2 /nobreak >nul
start http://localhost:5173

echo.
echo Application opened in browser!
echo.
echo Servers are running in minimized windows.
echo Close those windows to stop the servers.
echo.
timeout /t 2 /nobreak >nul
exit
