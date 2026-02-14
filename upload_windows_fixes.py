#!/usr/bin/env python3
"""
Script to upload the Windows installation fixes to the GitHub repository
using the GitHub agent.
"""

import os
from github_agent import GitHubAgent

def main():
    print("Uploading Windows installation fixes to GitHub repository...")
    print("=" * 60)

    # Initialize the GitHub agent with the config file
    agent = GitHubAgent(config_file="config.ini")

    # Connect to the repository
    repo_name = "Rohit-Mukherjee/Command_Analyzer_All"
    if not agent.connect_to_repo(repo_name):
        print("Failed to connect to the repository. Exiting.")
        return

    # List of files to upload/update
    files_to_upload = [
        "install.bat",           # Fixed batch installation script
        "install_fixed.ps1",     # PowerShell installation script
        "README.md",             # Updated README with Windows instructions
        "WINDOWS_INSTALLATION.md",  # Detailed Windows installation guide
        "check_installation.py", # Installation verification script
        "start_clta.bat",        # Windows start script
        "start_clta.ps1"         # PowerShell start script
    ]

    # Filter out files that don't exist
    existing_files = []
    for file_path in files_to_upload:
        if os.path.exists(file_path):
            existing_files.append(file_path)
        else:
            print(f"Warning: File {file_path} does not exist and will be skipped.")

    if not existing_files:
        print("No files to upload. Exiting.")
        return

    print(f"Files to upload: {existing_files}")

    # Upload the files with a descriptive commit message
    commit_message = "Fix Windows installation issues and add PowerShell support\n\n- Fixed install.bat with proper error handling and Python command detection\n- Added install_fixed.ps1 PowerShell installation script\n- Created detailed Windows installation guide\n- Updated README with Windows installation instructions\n- Added installation verification script\n- Added start scripts for Windows users"

    success = agent.create_or_update_multiple_files(existing_files, commit_message, "main")

    if success:
        print("\n✅ Successfully uploaded all files to the repository!")
        print("The Windows installation fixes have been pushed to your GitHub repository.")
    else:
        print("\n❌ Failed to upload files to the repository.")
        
if __name__ == "__main__":
    main()