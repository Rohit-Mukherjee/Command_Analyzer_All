#!/usr/bin/env python3
"""
Script to restore the original README and apply only the necessary Windows-specific additions.
"""

import os
from github import Github
import configparser

def main():
    print("Restoring original README and applying only Windows-specific additions...")
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

    # Get the repository's git commits to find the previous state
    try:
        commits = repo.get_commits()
        if commits.totalCount < 2:
            print("Not enough commits to find a previous state.")
            return
            
        # Find the original README content from an earlier commit
        original_readme = None
        for commit in commits.reversed:
            try:
                file_content = repo.get_contents("README.md", ref=commit.sha)
                content_str = file_content.decoded_content.decode('utf-8')
                # Check if this commit contains the original README (without our changes)
                if "Black Hat/DEF CON Readiness" in content_str and "Cross-Platform (40+ rules)" in content_str:
                    original_readme = content_str
                    print(f"Found original README in commit {commit.sha[:8]}")
                    break
            except:
                continue
        
        if original_readme:
            # Get current README SHA for update
            current_readme = repo.get_contents("README.md", ref="main")
            
            # Add Windows installation instructions to the original README
            windows_section = "\n\n**Note for Windows Users:** If the batch script doesn't work, you can also use the PowerShell script:\n```powershell\n# Run the PowerShell installation script\n.\\install_fixed.ps1\n```\n\nFor more detailed Windows installation instructions, see [WINDOWS_INSTALLATION.md](WINDOWS_INSTALLATION.md)."
            
            # Find where to insert the Windows note (after the existing installation section)
            if "On Windows:" in original_readme:
                # Insert our addition after the existing Windows installation instructions
                pos = original_readme.find("On Windows:") + len("On Windows:")
                updated_readme = original_readme[:pos] + windows_section + original_readme[pos:]
            else:
                # If no Windows section exists, append to the installation section
                install_pos = original_readme.find("### Manual Installation")
                if install_pos != -1:
                    updated_readme = original_readme[:install_pos] + windows_section + "\n\n" + original_readme[install_pos:]
                else:
                    updated_readme = original_readme + windows_section
            
            # Update the README with the original content plus our Windows additions
            repo.update_file(
                path="README.md",
                message="Restore original README with minimal Windows installation additions",
                content=updated_readme,
                sha=current_readme.sha,
                branch="main"
            )
            
            print("✅ Restored original README with minimal Windows installation additions")
        else:
            print("⚠️ Could not find original README content")
        
        # Also restore the original install.bat if possible
        original_install = None
        for commit in commits.reversed:
            try:
                file_content = repo.get_contents("install.bat", ref=commit.sha)
                original_install = file_content.decoded_content.decode('utf-8')
                print(f"Found original install.bat in commit {commit.sha[:8]}")
                break
            except:
                continue
        
        if original_install:
            # Get current install.bat SHA for update
            current_install = repo.get_contents("install.bat", ref="main")
            
            # Apply only minimal fixes to the original install.bat
            # Just add the most critical fixes without major restructuring
            fixed_install = original_install.replace(
                'python --version >nul 2>&1',
                '''REM Check if Python 3.8+ is installed (try both python and py commands)
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
)'''
            ).replace(
                'python -m venv clta_env',
                '%PYTHON_CMD% -m venv clta_env'
            ).replace(
                'call clta_env\\Scripts\\activate.bat',
                '''%PYTHON_CMD% -m venv clta_env
    if errorlevel 1 (
        echo ❌ Failed to create virtual environment.
        pause
        exit /b 1
    )
    call clta_env\\Scripts\\activate.bat
    if errorlevel 1 (
        echo ❌ Failed to activate virtual environment.
        pause
        exit /b 1
    )
    echo ✅ Virtual environment created and activated'''
            )
            
            # Update install.bat with minimal fixes
            repo.update_file(
                path="install.bat",
                message="Apply minimal fixes to install.bat for Windows compatibility",
                content=fixed_install,
                sha=current_install.sha,
                branch="main"
            )
            
            print("✅ Applied minimal fixes to install.bat")
        else:
            print("⚠️ Could not find original install.bat content")
        
        print("\n✅ Completed restoration with minimal necessary changes.")
        print("Original README restored with only essential Windows installation additions.")
        
    except Exception as e:
        print(f"❌ Error during restoration: {e}")

if __name__ == "__main__":
    main()