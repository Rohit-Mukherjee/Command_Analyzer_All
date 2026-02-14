#!/usr/bin/env python3
"""
Script to restore the original README content to the repository.
"""

import os
from github import Github
import configparser

def main():
    print("Restoring original README content to the repository...")
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

    # Read the original README content
    original_readme_path = "README_original_content.md"
    if not os.path.exists(original_readme_path):
        print(f"Original README content file not found: {original_readme_path}")
        return

    with open(original_readme_path, 'r', encoding='utf-8') as f:
        original_readme_content = f.read()

    try:
        # Get the current README file to get its SHA for the update operation
        current_readme = repo.get_contents("README.md", ref="main")
        
        # Update the README with the original content
        repo.update_file(
            path="README.md",
            message="Restore original Command Line Threat Analyzer README content",
            content=original_readme_content,
            sha=current_readme.sha,
            branch="main"
        )
        
        print("✅ Successfully restored original README content to the repository")
        
        # Also make sure the Windows-specific additions are preserved
        # Let's add just the Windows installation note to the original README
        windows_addition = "\n\n**Note for Windows Users:** If the batch script doesn't work, you can also use the PowerShell script:\n```powershell\n# Run the PowerShell installation script\n.\\install_fixed.ps1\n```\n\nFor more detailed Windows installation instructions, see [WINDOWS_INSTALLATION.md](WINDOWS_INSTALLATION.md)."
        
        # Get the updated README
        updated_readme = repo.get_contents("README.md", ref="main")
        current_content = updated_readme.decoded_content.decode('utf-8')
        
        # Add Windows note after the Windows installation section
        if "On Windows:" in current_content and "install.bat" in current_content:
            # Find the Windows installation section and add our note
            pos = current_content.find("install.bat") + len("install.bat")
            if "\\install_fixed.ps1" not in current_content:  # Check if our addition is already there
                final_content = current_content[:pos] + windows_addition + current_content[pos:]
                
                repo.update_file(
                    path="README.md",
                    message="Add Windows PowerShell installation instructions to README",
                    content=final_content,
                    sha=updated_readme.sha,
                    branch="main"
                )
                print("✅ Added Windows PowerShell installation instructions to README")
        
    except Exception as e:
        print(f"❌ Error updating README: {e}")

    # Also update install.bat to make sure it has the critical fixes
    try:
        # Read the fixed install.bat
        fixed_install_path = "install.bat"  # This is the fixed version
        if os.path.exists(fixed_install_path):
            with open(fixed_install_path, 'r', encoding='utf-8') as f:
                fixed_install_content = f.read()
            
            # Get the current install.bat file to get its SHA for the update operation
            current_install = repo.get_contents("install.bat", ref="main")
            
            # Update install.bat with the fixed version
            repo.update_file(
                path="install.bat",
                message="Update install.bat with Windows compatibility fixes",
                content=fixed_install_content,
                sha=current_install.sha,
                branch="main"
            )
            
            print("✅ Successfully updated install.bat with Windows compatibility fixes")
    except Exception as e:
        print(f"❌ Error updating install.bat: {e}")

    print("\n✅ Completed restoration of proper README content with Windows installation fixes preserved.")

if __name__ == "__main__":
    main()