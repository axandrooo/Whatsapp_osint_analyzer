@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" goto failed
set "HF_HUB_OFFLINE=1"
set "HF_HUB_DISABLE_TELEMETRY=1"
".venv\Scripts\python.exe" main.py
if errorlevel 1 goto failed
exit /b 0
:failed
echo Application did not start. Run INSTALL.bat first. Read the error above.
pause
exit /b 1
