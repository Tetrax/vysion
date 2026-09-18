@echo off
setlocal EnableExtensions EnableDelayedExpansion

echo ========================================
echo   FortiGate Audit Application Launcher
echo ========================================
echo.

REM Find a Python version supported by the pinned backend dependencies.
where py >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python launcher not found. Please install Python 3.10 to 3.13.
    pause
    exit /b 1
)

set "PYTHON_VERSION="
for %%V in (3.13 3.12 3.11 3.10) do (
    if not defined PYTHON_VERSION (
        py -%%V --version >nul 2>&1
        if not errorlevel 1 set "PYTHON_VERSION=%%V"
    )
)

if not defined PYTHON_VERSION (
    echo ERROR: No supported Python version was found.
    echo        Install Python 3.10, 3.11, 3.12 or 3.13.
    echo        Python 3.14 is not supported by the pinned dependencies.
    pause
    exit /b 1
)

echo     Using Python !PYTHON_VERSION!

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
set "REBUILD_VENV=0"
if not exist ".venv\Scripts\python.exe" set "REBUILD_VENV=1"

if "!REBUILD_VENV!"=="0" (
    findstr /b /c:"version = 3.10" /c:"version = 3.11" /c:"version = 3.12" /c:"version = 3.13" ".venv\pyvenv.cfg" >nul 2>&1
    if errorlevel 1 set "REBUILD_VENV=1"
)

if "!REBUILD_VENV!"=="1" (
    if exist ".venv" (
        echo     Removing incompatible Python virtual environment...
        rmdir /s /q ".venv"
        if exist ".venv" (
            ping 127.0.0.1 -n 2 >nul
            rmdir /s /q ".venv"
        )
        if exist ".venv" (
            echo ERROR: Failed to remove the incompatible virtual environment.
            echo        Close any Python process using modern_audit_app\backend\.venv and retry.
            pause
            exit /b 1
        )
    )
    echo     Creating Python virtual environment...
    py -!PYTHON_VERSION! -m venv .venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
)

REM Install backend dependencies when one or more imports are unavailable.
.venv\Scripts\python.exe -c "import fastapi, uvicorn, multipart, pydantic, openpyxl, docx, pandas, requests, bs4, PIL, msal" >nul 2>&1
if errorlevel 1 (
    echo     Installing backend dependencies...
    .venv\Scripts\python.exe -m pip install --disable-pip-version-check -r requirements.txt
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
    call npm install
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
ping 127.0.0.1 -n 4 >nul

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
ping 127.0.0.1 -n 3 >nul
start http://localhost:5173

echo.
echo Application opened in browser!
echo.
echo Servers are running in minimized windows.
echo Close those windows to stop the servers.
echo.
ping 127.0.0.1 -n 3 >nul
exit
