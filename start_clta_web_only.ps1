# PowerShell start script for Command Line Threat Analyzer on Windows
# This script directly launches the web application

Write-Host "🚀 Starting Command Line Threat Analyzer Web Application..." -ForegroundColor Green

# Check if virtual environment is active
if (-not $env:VIRTUAL_ENV) {
    Write-Host "⚠️  Virtual environment not active. Attempting to activate..." -ForegroundColor Yellow
    if (Test-Path "clta_env\Scripts\Activate.ps1") {
        & ".\clta_env\Scripts\Activate.ps1"
        if ($LASTEXITCODE -ne 0) {
            Write-Host "❌ Failed to activate virtual environment." -ForegroundColor Red
            Write-Host "Please run install.bat first to set up the environment." -ForegroundColor Red
            Pause
            exit 1
        }
        Write-Host "✅ Virtual environment activated" -ForegroundColor Green
    } else {
        Write-Host "❌ Virtual environment not found. Please run install.bat first." -ForegroundColor Red
        Pause
        exit 1
    }
}

Write-Host ""
Write-Host "Starting the web application..." -ForegroundColor Yellow
Write-Host "Access the application at http://localhost:8501 in your browser" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press Ctrl+C to stop the application" -ForegroundColor Yellow
Write-Host ""

# Launch the web application directly
& streamlit run web_app.py

Write-Host ""
Write-Host "Web application has been closed." -ForegroundColor Yellow
Write-Host ""

Pause