# PowerShell start script for Command Line Threat Analyzer on Windows

Write-Host "🚀 Starting Command Line Threat Analyzer..." -ForegroundColor Green

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
Write-Host "📋 Available Options:" -ForegroundColor Cyan
Write-Host "  1. Run Log Analyzer" -ForegroundColor White
Write-Host "  2. Run Web App" -ForegroundColor White
Write-Host "  3. Run Rules Wizard" -ForegroundColor White
Write-Host "  4. Run Dashboard" -ForegroundColor White
Write-Host "  5. Check Installation" -ForegroundColor White
Write-Host ""

$choice = Read-Host "Enter your choice (1-5)"

switch ($choice) {
    "1" {
        Write-Host "Starting Log Analyzer..." -ForegroundColor Yellow
        python log_analyzer.py
    }
    "2" {
        Write-Host "Starting Web App..." -ForegroundColor Yellow
        streamlit run web_app.py
    }
    "3" {
        Write-Host "Starting Rules Wizard..." -ForegroundColor Yellow
        streamlit run rules_wizard_app.py
    }
    "4" {
        Write-Host "Starting Dashboard..." -ForegroundColor Yellow
        streamlit run dashboard.py
    }
    "5" {
        Write-Host "Checking Installation..." -ForegroundColor Yellow
        python check_installation.py
    }
    default {
        Write-Host "Invalid choice." -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")