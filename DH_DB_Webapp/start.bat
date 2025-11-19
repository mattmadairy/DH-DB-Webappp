@echo off
REM Quick start script for DH Member Database Web Application (Windows)

echo Starting DH Member Database Web Application...
echo.

REM Check if virtual environment exists
if not exist venv (
    echo Virtual environment not found. Running installation...
    call install.bat
    if errorlevel 1 (
        echo Installation failed. Please check errors above.
        pause
        exit /b 1
    )
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Check if database exists
if not exist members.db (
    echo Database not found. Initializing...
    python init_db.py
)

REM Start the application
echo.
echo ========================================
echo Application starting...
echo Open your browser to: http://127.0.0.1:5000
echo Press Ctrl+C to stop the server
echo ========================================
echo.

python app.py
