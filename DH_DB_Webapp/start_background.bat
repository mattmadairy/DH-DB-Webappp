@echo off
REM Run the app in background without console window

echo Starting DH Member Database in background...

REM Check if virtual environment exists
if exist venv\Scripts\pythonw.exe (
    start "" venv\Scripts\pythonw.exe app.py
) else if exist venv\Scripts\python.exe (
    start "" /B venv\Scripts\python.exe app.py
) else (
    start "" /B pythonw.exe app.py
)

echo Application started in background.
echo Access at: http://127.0.0.1:5000
echo.
echo To stop the application, use Task Manager to end python.exe or pythonw.exe
timeout /t 3 /nobreak >nul
