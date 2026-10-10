@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" goto failed
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --distpath dist --workpath build Whatsapp_Osint_analyzer.spec
if errorlevel 1 goto failed
if exist "models\small\model.bin" (
    robocopy "models\small" "dist\models\small" /E /R:1 /W:1 /NFL /NDL
    if errorlevel 8 goto copy_failed
) else (
    echo Speech model not found. Run DOWNLOAD_MODEL.bat, then build again or select its folder in the app.
)
echo.
echo EXE: dist\Whatsapp_Osint_analyzer.exe
echo If the model was downloaded, it is copied into dist\models\small.
echo When moving the app, copy the EXE and the models folder together.
pause
exit /b 0
:copy_failed
echo EXE built, but the model could not be copied. Copy models next to the EXE manually.
pause
exit /b 1
:failed
echo BUILD FAILED. Do not launch an old EXE. Run INSTALL.bat and read the error above.
pause
exit /b 1
