@echo off
REM Fixed installation script for Command Line Threat Analyzer on Windows

echo 🚀 Installing Command Line Threat Analyzer...

REM Check if Python 3.8+ is installed (try both python and py commands)
python --version >nul 2>&1
if errorlevel 1 (
    py --version >nul 2>&1
    if errorlevel 1 (
        echo ❌ Python is not installed. Please install Python 3.8 or higher.
        pause
        exit /b 1
    ) else (
        set PYTHON_CMD=py
    )
) else (
    set PYTHON_CMD=python
)

REM Get Python version
for /f "tokens=2 delims= " %%i in ('%PYTHON_CMD% --version 2^>^&1') do set PYTHON_VERSION=%%i
echo ✅ Python %PYTHON_VERSION% detected

REM Parse version numbers
for /f "tokens=1,2,3 delims=." %%a in ("%PYTHON_VERSION%") do (
    set MAJOR=%%b
    set MINOR=%%c
)

REM Check major version
if %MAJOR% lss 3 (
    echo ❌ Python version is too old. Please upgrade to Python 3.8 or higher.
    pause
    exit /b 1
)

REM Check minor version if major is 3
if %MAJOR% equ 3 (
    if %MINOR% lss 8 (
        echo ❌ Python version is too old. Please upgrade to Python 3.8 or higher.
        pause
        exit /b 1
    )
)

REM Check if pip is installed
%PYTHON_CMD% -m pip --version >nul 2>&1
if errorlevel 1 (
    echo ❌ pip is not installed. Attempting to install...
    %PYTHON_CMD% -m ensurepip --upgrade
    if errorlevel 1 (
        echo ❌ Failed to install pip. Please install pip manually.
        pause
        exit /b 1
    )
)

echo ✅ pip is available

REM Create virtual environment if not already in one
if "%VIRTUAL_ENV%"=="" (
    echo 📦 Creating virtual environment...
    %PYTHON_CMD% -m venv clta_env
    if errorlevel 1 (
        echo ❌ Failed to create virtual environment.
        pause
        exit /b 1
    )
    call clta_env\Scripts\activate.bat
    if errorlevel 1 (
        echo ❌ Failed to activate virtual environment.
        pause
        exit /b 1
    )
    echo ✅ Virtual environment created and activated
) else (
    echo ⚠️  Already in a virtual environment
)

REM Upgrade pip
echo ⬆️  Upgrading pip...
python -m pip install --upgrade pip
if errorlevel 1 (
    echo ⚠️  Warning: Failed to upgrade pip, continuing anyway...
)

REM Check if requirements.txt exists before installing
if exist requirements.txt (
    echo 📦 Installing dependencies from requirements.txt...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ⚠️  Warning: Failed to install some dependencies from requirements.txt
    )
) else (
    echo ⚠️  requirements.txt not found, installing dependencies from pyproject.toml...
)

REM Install the package in development mode
echo 📦 Installing Command Line Threat Analyzer in development mode...
pip install -e .
if errorlevel 1 (
    echo ❌ Failed to install the package.
    pause
    exit /b 1
)

echo ✅ Installation completed successfully!

echo.
echo 📋 Usage Instructions:
echo   1. To run the analyzer: python log_analyzer.py
echo   2. To run the web app: streamlit run web_app.py
echo   3. To run the rules wizard: streamlit run rules_wizard_app.py
echo   4. To run the dashboard: streamlit run dashboard.py
echo.
echo 💡 Tip: Activate the virtual environment before running the tools:
if "%VIRTUAL_ENV%"=="" (
    echo   clta_env\Scripts\activate.bat
)
echo.
echo 🔒 Remember to deactivate the environment when done:
echo   deactivate
echo.
pause