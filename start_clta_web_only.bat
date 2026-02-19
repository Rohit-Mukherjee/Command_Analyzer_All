@echo off
REM Start script for Command Line Threat Analyzer on Windows
REM This script directly launches the web application

echo 🚀 Starting Command Line Threat Analyzer Web Application...
echo.

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
echo Starting the web application...
echo Access the application at http://localhost:8501 in your browser
echo.
echo Press Ctrl+C to stop the application
echo.

REM Launch the web application directly
streamlit run web_app.py

echo.
echo Web application has been closed.
echo.
pause