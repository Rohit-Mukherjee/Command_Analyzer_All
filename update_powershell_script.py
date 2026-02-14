#!/usr/bin/env python3
"""
Script to update the PowerShell installation script with execution policy handling.
"""

import os
from github import Github
import configparser

def main():
    print("Updating PowerShell installation script with execution policy handling...")
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

    # Read the improved PowerShell script
    improved_script_path = "install_fixed_with_execution_policy.ps1"
    if not os.path.exists(improved_script_path):
        print(f"Improved PowerShell script not found: {improved_script_path}")
        return

    with open(improved_script_path, 'r', encoding='utf-8') as f:
        improved_script_content = f.read()

    try:
        # Get the current install_fixed.ps1 file to get its SHA for the update operation
        current_ps_script = repo.get_contents("install_fixed.ps1", ref="main")
        
        # Update the PowerShell script with the improved version
        repo.update_file(
            path="install_fixed.ps1",
            message="Update PowerShell script with execution policy handling",
            content=improved_script_content,
            sha=current_ps_script.sha,
            branch="main"
        )
        
        print("✅ Successfully updated install_fixed.ps1 with execution policy handling")
        
    except Exception as e:
        print(f"❌ Error updating install_fixed.ps1: {e}")

    # Also update the WINDOWS_INSTALLATION.md to include instructions about execution policy
    try:
        current_md = repo.get_contents("WINDOWS_INSTALLATION.md", ref="main")
        current_md_content = current_md.decoded_content.decode('utf-8')
        
        # Add execution policy information to the troubleshooting section
        execution_policy_text = "\n### Execution Policy Issues\nIf you encounter an error about scripts being disabled on your system:\n```\nFile ... cannot be loaded because running scripts is disabled on this system.\n```\n\nThis is due to PowerShell's execution policy. You have several options:\n\n1. **Change execution policy** (requires admin rights):\n   ```powershell\n   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser\n   ```\n\n2. **Run with bypass policy**:\n   ```powershell\n   powershell -ExecutionPolicy Bypass -File .\\install_fixed.ps1\n   ```\n\n3. **Run in Command Prompt** using the batch script instead:\n   ```cmd\n   install.bat\n   ```"
        
        # Find the Troubleshooting section and add our execution policy info
        if "Troubleshooting Common Issues" in current_md_content:
            pos = current_md_content.find("Troubleshooting Common Issues") + len("Troubleshooting Common Issues")
            updated_md_content = current_md_content[:pos] + execution_policy_text + current_md_content[pos:]
        else:
            updated_md_content = current_md_content + "\n\n## Troubleshooting\n" + execution_policy_text
        
        repo.update_file(
            path="WINDOWS_INSTALLATION.md",
            message="Add PowerShell execution policy troubleshooting instructions",
            content=updated_md_content,
            sha=current_md.sha,
            branch="main"
        )
        
        print("✅ Successfully updated WINDOWS_INSTALLATION.md with execution policy instructions")
        
    except Exception as e:
        print(f"❌ Error updating WINDOWS_INSTALLATION.md: {e}")

    print("\n✅ Completed updating PowerShell script with execution policy handling.")

if __name__ == "__main__":
    main()