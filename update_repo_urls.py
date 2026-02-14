#!/usr/bin/env python3
"""
Script to update the README with correct repository URLs pointing to your repository.
"""

import os
from github import Github
import configparser

def main():
    print("Updating README with correct repository URLs...")
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

    try:
        # Get the current README file
        current_readme = repo.get_contents("README.md", ref="main")
        current_content = current_readme.decoded_content.decode('utf-8')
        
        # Update URLs to point to the correct repository
        updated_content = current_content.replace(
            "git clone <repository-url>\ncd command-line-analyzer",
            f"git clone https://github.com/{repo_name}\ncd Command_Analyzer_All"
        )
        
        # Also update any other references to the generic name
        updated_content = updated_content.replace(
            "cd command-line-analyzer",
            "cd Command_Analyzer_All"
        )
        
        # Update the repository name references if they exist
        updated_content = updated_content.replace(
            "<repository-url>",
            f"https://github.com/{repo_name}"
        )

        # Update the README with corrected URLs
        repo.update_file(
            path="README.md",
            message="Update repository URLs to point to correct repository",
            content=updated_content,
            sha=current_readme.sha,
            branch="main"
        )
        
        print("✅ Successfully updated README with correct repository URLs")
        
    except Exception as e:
        print(f"❌ Error updating README: {e}")

    try:
        # Also update the install.sh file if it exists in the repository
        current_install_sh = repo.get_contents("install.sh", ref="main")
        current_install_sh_content = current_install_sh.decoded_content.decode('utf-8')
        
        # Update URLs in install.sh
        updated_install_sh_content = current_install_sh_content.replace(
            "<repository-url>",
            f"https://github.com/{repo_name}"
        ).replace(
            "command-line-analyzer",
            "Command_Analyzer_All"
        )
        
        # Update install.sh with corrected URLs
        repo.update_file(
            path="install.sh",
            message="Update repository URLs in install script",
            content=updated_install_sh_content,
            sha=current_install_sh.sha,
            branch="main"
        )
        
        print("✅ Successfully updated install.sh with correct repository URLs")
        
    except Exception as e:
        print(f"⚠️  Could not update install.sh (may not exist in repository): {e}")

    print(f"\n✅ Completed updating repository URLs to point to https://github.com/{repo_name}")

if __name__ == "__main__":
    main()