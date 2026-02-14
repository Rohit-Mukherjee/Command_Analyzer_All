#!/usr/bin/env python3
"""
Script to update the WINDOWS_INSTALLATION.md file with simplified usage instructions.
"""

import os
from github import Github
import configparser

def main():
    print("Updating WINDOWS_INSTALLATION.md with simplified usage instructions...")
    print("=" * 60)

    # Read the config file to get the token
    config_file = "config.ini"
    if os.path.exists(config_file):
        config = configparser.ConfigParser()
        config.read(config_file)
        token = config['GITHUB']['token']
        repo_name = config['REPOSITORY']['full_name']
    else:
        print("Config file not found. Exiting.")
        return

    # Initialize GitHub client
    g = Github(token)
    
    try:
        repo = g.get_repo(repo_name)
        print(f"Successfully connected to repository: {repo_name}")
    except Exception as e:
        print(f"Error connecting to repository: {e}")
        return

    # Define the updated content for WINDOWS_INSTALLATION.md
    updated_content = """# Installation Guide for Windows

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
   .\\install_fixed.ps1
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
   clta_env\\Scripts\\activate.bat
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

### Python Not Found
If you get an error saying Python is not found:
- Make sure Python is installed and added to your PATH
- Try using `py` command instead of `python` (Windows feature)

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
   powershell -ExecutionPolicy Bypass -File .\\install_fixed.ps1
   ```

3. **Run in Command Prompt** using the batch script instead:
   ```cmd
   install.bat
   ```

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

### Simple Usage Command
For easiest usage, run the start script which provides a menu:
```
start_clta.bat
```

### Virtual Environment Management
Every time you want to use the tools, you need to activate the virtual environment first:
```
clta_env\\Scripts\\activate.bat
```

Then you can run any of the commands mentioned above.

### Simplified Workflow
1. **Activate virtual environment** (every new command prompt session):
   ```
   clta_env\\Scripts\\activate.bat
   ```

2. **Run the tool you want**:
   - For web interface: `streamlit run web_app.py`
   - For command line analysis: `python log_analyzer.py`
   - For rule creation: `streamlit run rules_wizard_app.py`
   - For dashboard: `streamlit run dashboard.py`
   - For menu interface: `start_clta.bat`

Remember to deactivate the environment when done:
```
deactivate
```
"""

    try:
        # Get the current WINDOWS_INSTALLATION.md file to get its SHA for the update operation
        current_md = repo.get_contents("WINDOWS_INSTALLATION.md", ref="main")
        
        # Update the WINDOWS_INSTALLATION.md with the updated content
        repo.update_file(
            path="WINDOWS_INSTALLATION.md",
            message="Update Windows installation guide with simplified usage instructions",
            content=updated_content,
            sha=current_md.sha,
            branch="main"
        )
        
        print("✅ Successfully updated WINDOWS_INSTALLATION.md with simplified usage instructions")
        
    except Exception as e:
        print(f"❌ Error updating WINDOWS_INSTALLATION.md: {e}")

    print("\n✅ Completed updating Windows installation guide.")

if __name__ == "__main__":
    main()