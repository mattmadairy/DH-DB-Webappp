@echo off
REM Production startup script for Windows

echo ========================================
echo DH Member Database - Production Mode
echo ========================================
echo.

REM Activate virtual environment if it exists
if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
)

REM Check if database exists
if not exist members.db (
    echo Initializing database...
    python init_db.py
    echo.
)

REM Start with Waitress production server
echo Starting production server...
echo Access the application at: http://localhost:8080
echo Press Ctrl+C to stop
echo.

python run_production.py
