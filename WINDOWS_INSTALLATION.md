# Installation Guide for Windows

## Prerequisites
- Python 3.8 or higher installed on your system
- Windows Command Prompt (cmd) or PowerShell

## Installation Methods

### Method 1: Using the Batch Script (Recommended)
1. Open Command Prompt as Administrator
2. Navigate to the project directory
3. Run the installation script:
   ```
   install.bat
   ```

### Method 2: Using PowerShell Script
1. Open PowerShell as Administrator
2. Navigate to the project directory
3. Run the installation script:
   ```powershell
   .\install_fixed.ps1
   ```

### Method 3: Manual Installation
1. Open Command Prompt
2. Navigate to the project directory
3. Create a virtual environment:
   ```
   python -m venv clta_env
   ```
4. Activate the virtual environment:
   ```
   clta_env\Scripts\activate.bat
   ```
5. Upgrade pip:
   ```
   python -m pip install --upgrade pip
   ```
6. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
7. Install the package in development mode:
   ```
   pip install -e .
   ```

## Troubleshooting Common Issues
### Execution Policy Issues
If you encounter an error about scripts being disabled on your system:
```
File ... cannot be loaded because running scripts is disabled on this system.
```

This is due to PowerShell's execution policy. You have several options:

1. **Change execution policy** (requires admin rights):
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

2. **Run with bypass policy**:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\install_fixed.ps1
   ```

3. **Run in Command Prompt** using the batch script instead:
   ```cmd
   install.bat
   ```

### Python Not Found
If you get an error saying Python is not found:
- Make sure Python is installed and added to your PATH
- Try using `py` command instead of `python` (Windows feature)

### Permission Errors
- Run Command Prompt or PowerShell as Administrator
- Make sure you have write permissions to the project directory

### Virtual Environment Activation Issues
- Make sure you're in the correct directory
- Check that the `clta_env` folder was created successfully

## Post-Installation Usage

After successful installation, you can run the tools:

1. To run the analyzer: `python log_analyzer.py`
2. To run the web app: `streamlit run web_app.py`
3. To run the rules wizard: `streamlit run rules_wizard_app.py`
4. To run the dashboard: `streamlit run dashboard.py`

Remember to activate the virtual environment before running the tools:
```
clta_env\Scripts\activate.bat
```

To deactivate the environment when done:
```
deactivate
```