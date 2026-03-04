@echo off
REM Safe Dependency Installation Script for Windows
REM This script installs/updates dependencies without affecting your data

echo === DH Webapp Dependency Installation ===
echo This will install/update Python dependencies safely
echo.

REM Check if we're in the right directory
if not exist "DH_DB_Webapp\requirements.txt" (
    echo Error: requirements.txt not found in DH_DB_Webapp\ directory
    echo Please run this script from the project root directory
    goto :error
)

cd DH_DB_Webapp

echo 📦 Updating pip...
python -m pip install --upgrade pip
if %errorlevel% neq 0 goto :error

echo.
echo 📦 Installing production dependencies...
python -m pip install -r requirements.txt
if %errorlevel% neq 0 goto :error

echo.
echo ✅ Dependencies installed successfully!
echo.
echo To install development dependencies as well, run:
echo python -m pip install -r requirements-dev.txt
echo.
echo To test the installation:
echo python -c "import app; print('✅ App imports successfully')"
echo.
echo To run the application:
echo python app.py
echo.
goto :end

:error
echo ❌ Installation failed!
echo Check the error messages above and try again.
exit /b 1

:end