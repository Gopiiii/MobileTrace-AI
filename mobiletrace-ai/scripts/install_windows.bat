@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_windows.ps1"
set RC=%ERRORLEVEL%
if %RC% NEQ 0 (
    echo.
    echo MobileTrace AI installation failed with exit code %RC%.
) else (
    echo.
    echo Installation finished.
)
pause
exit /b %RC%
