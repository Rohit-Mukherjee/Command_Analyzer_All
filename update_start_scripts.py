#!/usr/bin/env python3
"""
Script to update the start scripts to only launch the web application.
"""

import os
from github import Github
import configparser

def main():
    print("Updating start scripts to only launch the web application...")
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

    # Read the updated start_clta.bat content
    with open("start_clta_web_only.bat", 'r', encoding='utf-8') as f:
        updated_bat_content = f.read()

    # Read the updated start_clta.ps1 content
    with open("start_clta_web_only.ps1", 'r', encoding='utf-8') as f:
        updated_ps_content = f.read()

    try:
        # Get the current start_clta.bat file to get its SHA for the update operation
        current_bat = repo.get_contents("start_clta.bat", ref="main")
        
        # Update the start_clta.bat with the new content
        repo.update_file(
            path="start_clta.bat",
            message="Update start script to only launch the web application",
            content=updated_bat_content,
            sha=current_bat.sha,
            branch="main"
        )
        
        print("✅ Successfully updated start_clta.bat to only launch the web application")
        
    except Exception as e:
        print(f"❌ Error updating start_clta.bat: {e}")

    try:
        # Get the current start_clta.ps1 file to get its SHA for the update operation
        current_ps = repo.get_contents("start_clta.ps1", ref="main")
        
        # Update the start_clta.ps1 with the new content
        repo.update_file(
            path="start_clta.ps1",
            message="Update PowerShell start script to only launch the web application",
            content=updated_ps_content,
            sha=current_ps.sha,
            branch="main"
        )
        
        print("✅ Successfully updated start_clta.ps1 to only launch the web application")
        
    except Exception as e:
        print(f"❌ Error updating start_clta.ps1: {e}")

    print("\n✅ Completed updating start scripts to only launch the web application.")

if __name__ == "__main__":
    main()