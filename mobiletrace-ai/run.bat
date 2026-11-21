@echo off
rem MobileTrace AI launcher (double-click).  Usage: run.bat [web|desktop|setup|test|doctor]
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
    echo Node.js was not found. Install Node 20.11+ ^(22 LTS recommended^) from https://nodejs.org and run this again.
    pause
    exit /b 1
)
node run.mjs %*
set RC=%ERRORLEVEL%
if not "%RC%"=="0" (
    echo.
    echo MobileTrace AI stopped with exit code %RC%.
    pause
)
exit /b %RC%
