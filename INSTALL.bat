@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    py -3.11 -m venv .venv
    if errorlevel 1 goto failed
)
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed
echo.
echo Installation complete. Run DOWNLOAD_MODEL.bat once, then START.bat.
pause
exit /b 0
:failed
echo.
echo INSTALL FAILED. Install Python 3.11 x64 with the Python Launcher and retry.
pause
exit /b 1
