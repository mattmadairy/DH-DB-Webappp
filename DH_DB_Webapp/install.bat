@echo off
REM Installation script for DH Member Database Web Application (Windows)

echo ========================================
echo DH Member Database - Installation
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed. Installing Python...
    echo.
    
    REM Check if winget is available (Windows 10/11)
    winget --version >nul 2>&1
    if not errorlevel 1 (
        echo Installing Python using Windows Package Manager...
        winget install -e --id Python.Python.3.11 --silent --accept-package-agreements --accept-source-agreements
        if errorlevel 1 (
            echo WARNING: Automated installation failed.
            goto :manual_install
        )
        echo Python installed successfully!
        echo Please close this window and run install.bat again.
        pause
        exit /b 0
    ) else (
        goto :manual_install
    )
) else (
    echo Step 1/5: Python found
    python --version
    echo.
    goto :continue_install
)

:manual_install
echo.
echo ========================================
echo Manual Python Installation Required
echo ========================================
echo.
echo Python Package Manager (winget) not available.
echo.
echo Please install Python manually:
echo   1. Visit: https://www.python.org/downloads/
echo   2. Download Python 3.8 or higher
echo   3. Run the installer
echo   4. IMPORTANT: Check "Add Python to PATH" during installation
echo   5. After installation, run this script again
echo.
echo Opening Python download page in your browser...
start https://www.python.org/downloads/
pause
exit /b 1

:continue_install
echo.

REM Create virtual environment
echo Step 2/5: Creating virtual environment...
if exist venv (
    echo Virtual environment already exists, skipping...
) else (
    python -m venv venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
    echo Virtual environment created successfully
)
echo.

REM Activate virtual environment and install dependencies
echo Step 3/5: Installing dependencies...
call venv\Scripts\activate.bat
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)
echo Dependencies installed successfully
echo.

REM Check dependencies
echo Step 4/5: Verifying dependencies...
python check_dependencies.py
if errorlevel 1 (
    echo WARNING: Some dependencies may be missing
    echo Continuing with installation...
)
echo.

REM Initialize database
echo Step 5/5: Initializing database...
python init_db.py
if errorlevel 1 (
    echo ERROR: Failed to initialize database
    pause
    exit /b 1
)
echo Database initialized successfully
echo.

echo ========================================
echo Installation Complete!
echo ========================================
echo.
echo To run the application:
echo   1. Activate virtual environment: venv\Scripts\activate.bat
echo   2. Run the app: python app.py
echo   3. Open browser: http://127.0.0.1:5000
echo.
echo Or simply run: start.bat
echo.
pause
