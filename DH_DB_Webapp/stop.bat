@echo off
REM Stop the background application

echo Stopping DH Member Database...

REM Kill python processes running app.py
taskkill /F /IM pythonw.exe /FI "WINDOWTITLE eq app.py" 2>nul
taskkill /F /IM python.exe /FI "WINDOWTITLE eq app.py" 2>nul

REM Alternative: kill all python processes (use with caution)
REM taskkill /F /IM pythonw.exe 2>nul
REM taskkill /F /IM python.exe 2>nul

echo Application stopped.
pause
