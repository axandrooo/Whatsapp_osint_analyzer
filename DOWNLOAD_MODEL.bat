@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" goto failed
echo Downloads the multilingual small speech model. Internet is required only for this step.
echo No documents, chats or audio files are uploaded.
set "HF_HUB_OFFLINE=0"
set "HF_HUB_DISABLE_TELEMETRY=1"
".venv\Scripts\python.exe" -c "from faster_whisper.utils import download_model; download_model('small', output_dir='models/small')"
if errorlevel 1 goto failed
echo Model downloaded. Run START.bat.
pause
exit /b 0
:failed
echo DOWNLOAD FAILED. Run INSTALL.bat first and check your Internet connection.
echo You may also copy a complete faster-whisper model folder from another computer.
pause
exit /b 1
