@echo off
REM Start script for Command Line Threat Analyzer on Windows

echo 🚀 Starting Command Line Threat Analyzer...

REM Check if virtual environment is active
if "%VIRTUAL_ENV%"=="" (
    echo ⚠️  Virtual environment not active. Attempting to activate...
    if exist clta_env\Scripts\activate.bat (
        call clta_env\Scripts\activate.bat
        if errorlevel 1 (
            echo ❌ Failed to activate virtual environment.
            echo Please run install.bat first to set up the environment.
            pause
            exit /b 1
        )
        echo ✅ Virtual environment activated
    ) else (
        echo ❌ Virtual environment not found. Please run install.bat first.
        pause
        exit /b 1
    )
)

echo.
echo 📋 Available Options:
echo   1. Run Log Analyzer
echo   2. Run Web App
echo   3. Run Rules Wizard
echo   4. Run Dashboard
echo   5. Check Installation
echo.
set /p choice="Enter your choice (1-5): "

if "%choice%"=="1" (
    echo Starting Log Analyzer...
    python log_analyzer.py
) else if "%choice%"=="2" (
    echo Starting Web App...
    streamlit run web_app.py
) else if "%choice%"=="3" (
    echo Starting Rules Wizard...
    streamlit run rules_wizard_app.py
) else if "%choice%"=="4" (
    echo Starting Dashboard...
    streamlit run dashboard.py
) else if "%choice%"=="5" (
    echo Checking Installation...
    python check_installation.py
) else (
    echo Invalid choice.
)

echo.
echo Press any key to continue...
pause >nul