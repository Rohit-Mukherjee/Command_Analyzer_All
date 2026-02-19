# PowerShell installation script for Command Line Threat Analyzer on Windows

Write-Host "🚀 Installing Command Line Threat Analyzer..." -ForegroundColor Green

# Check if Python 3.8+ is installed
$pythonCmd = ""
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonVersion = $(python --version 2>&1)
    $pythonCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonVersion = $(py --version 2>&1)
    $pythonCmd = "py"
} else {
    Write-Host "❌ Python is not installed. Please install Python 3.8 or higher." -ForegroundColor Red
    Pause
    exit 1
}

# Extract version numbers
$versionMatch = [regex]::Match($pythonVersion, '\d+\.(\d+)\.(\d+)')
$major = [int]$versionMatch.Groups[1].Value
$minor = [int]$versionMatch.Groups[2].Value

Write-Host "✅ Python $($pythonVersion.Split(' ')[1]) detected" -ForegroundColor Green

# Check version
if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 8)) {
    Write-Host "❌ Python version is too old. Please upgrade to Python 3.8 or higher." -ForegroundColor Red
    Pause
    exit 1
}

# Check if pip is installed
try {
    & $pythonCmd -m pip --version > $null
    Write-Host "✅ pip is available" -ForegroundColor Green
} catch {
    Write-Host "❌ pip is not installed. Attempting to install..." -ForegroundColor Yellow
    & $pythonCmd -m ensurepip --upgrade
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to install pip. Please install pip manually." -ForegroundColor Red
        Pause
        exit 1
    }
    Write-Host "✅ pip installed successfully" -ForegroundColor Green
}

# Create virtual environment if not already in one
if (-not $env:VIRTUAL_ENV) {
    Write-Host "📦 Creating virtual environment..." -ForegroundColor Yellow
    & $pythonCmd -m venv clta_env
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to create virtual environment." -ForegroundColor Red
        Pause
        exit 1
    }
    
    # Activate virtual environment
    & ".\clta_env\Scripts\Activate.ps1"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to activate virtual environment." -ForegroundColor Red
        Pause
        exit 1
    }
    
    Write-Host "✅ Virtual environment created and activated" -ForegroundColor Green
} else {
    Write-Host "⚠️  Already in a virtual environment" -ForegroundColor Yellow
}

# Upgrade pip
Write-Host "⬆️  Upgrading pip..." -ForegroundColor Yellow
& python -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    Write-Host "⚠️  Warning: Failed to upgrade pip, continuing anyway..." -ForegroundColor Yellow
}

# Check if requirements.txt exists before installing
if (Test-Path "requirements.txt") {
    Write-Host "📦 Installing dependencies from requirements.txt..." -ForegroundColor Yellow
    & pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "⚠️  Warning: Failed to install some dependencies from requirements.txt" -ForegroundColor Yellow
    }
} else {
    Write-Host "⚠️  requirements.txt not found, installing dependencies from pyproject.toml..." -ForegroundColor Yellow
}

# Install the package in development mode
Write-Host "📦 Installing Command Line Threat Analyzer in development mode..." -ForegroundColor Yellow
& pip install -e .
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to install the package." -ForegroundColor Red
    Pause
    exit 1
}

Write-Host "✅ Installation completed successfully!" -ForegroundColor Green

Write-Host ""
Write-Host "📋 Usage Instructions:" -ForegroundColor Cyan
Write-Host "  1. To run the analyzer: python log_analyzer.py"
Write-Host "  2. To run the web app: streamlit run web_app.py"
Write-Host "  3. To run the rules wizard: streamlit run rules_wizard_app.py"
Write-Host "  4. To run the dashboard: streamlit run dashboard.py"
Write-Host ""
Write-Host "💡 Tip: Activate the virtual environment before running the tools:" -ForegroundColor Cyan
if (-not $env:VIRTUAL_ENV) {
    Write-Host "  clta_env\Scripts\Activate.ps1  # In PowerShell"
    Write-Host "  clta_env\Scripts\activate.bat  # In Command Prompt"
}
Write-Host ""
Write-Host "🔒 Remember to deactivate the environment when done:" -ForegroundColor Cyan
Write-Host "  deactivate"
Write-Host ""

Pause