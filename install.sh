#!/bin/bash
# Installation script for Command Line Threat Analyzer

echo "🚀 Installing Command Line Threat Analyzer..."

# Check if Python 3.8+ is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
MIN_VERSION="3.8"

if [[ "$(printf '%s\n' "$MIN_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$MIN_VERSION" ]]; then
    echo "❌ Python version $PYTHON_VERSION is too old. Please upgrade to Python 3.8 or higher."
    exit 1
fi

echo "✅ Python version $PYTHON_VERSION detected"

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip is not installed. Attempting to install..."
    python3 -m ensurepip --upgrade
    if ! command -v pip3 &> /dev/null; then
        echo "❌ Failed to install pip. Please install pip manually."
        exit 1
    fi
fi

echo "✅ pip is available"

# Create virtual environment if not already in one
if [ -z "$VIRTUAL_ENV" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv clta_env
    source clta_env/bin/activate
    echo "✅ Virtual environment created and activated"
else
    echo "⚠️  Already in a virtual environment"
fi

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# Install the package in development mode
echo "📦 Installing Command Line Threat Analyzer..."
pip install -e .

echo "✅ Installation completed successfully!"

echo ""
echo "📋 Usage Instructions:"
echo "  1. To run the analyzer: python log_analyzer.py"
echo "  2. To run the web app: streamlit run web_app.py"
echo "  3. To run the rules wizard: streamlit run rules_wizard_app.py"
echo "  4. To run the dashboard: streamlit run dashboard.py"
echo ""
echo "💡 Tip: Activate the virtual environment before running the tools:"
if [ -z "$VIRTUAL_ENV" ]; then
    echo "  source clta_env/bin/activate  # On Linux/Mac"
    echo "  source clta_env/Scripts/activate  # On Windows with Git Bash"
    echo "  clta_env\Scripts\activate.bat  # On Windows with Command Prompt"
fi
echo ""
echo "🔒 Remember to deactivate the environment when done:"
echo "  deactivate"