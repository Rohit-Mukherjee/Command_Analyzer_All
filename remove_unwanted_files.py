#!/usr/bin/env python3
"""
Script to remove the GitHub agent files that were incorrectly uploaded
to the repository.
"""

import os
from github import Github
import configparser

def main():
    print("Removing GitHub agent files from the repository...")
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

    # List of files to remove (these are the GitHub agent files that were incorrectly uploaded)
    files_to_remove = [
        "config.ini",              # Configuration file with token
        "debug_readme_update.py",  # GitHub agent debug file
        "github_agent.py",         # GitHub agent main file
        "README_CodeProjects.md",  # Unwanted README
        "update_readme.py",        # GitHub agent utility
        "upload_code_projects.py", # GitHub agent utility
        "upload_notes.py",         # GitHub agent utility
        "run_agent.py",            # GitHub agent runner
        "upload_windows_fixes.py", # Our upload script
        "remove_unwanted_files.py" # This script
    ]

    print(f"Attempting to remove the following files:")
    for file_path in files_to_remove:
        print(f"  - {file_path}")

    # Delete the files one by one
    for file_path in files_to_remove:
        try:
            # Check if file exists in the repo
            contents = repo.get_contents(file_path, ref="main")
            
            # Delete the file
            repo.delete_file(file_path, 
                           f"Remove {file_path} - unintended upload", 
                           contents.sha, 
                           branch="main")
            print(f"✅ Deleted: {file_path}")
        except Exception as e:
            print(f"⚠️  Could not delete {file_path}: {str(e)} (may not exist)")

    print("\n✅ Completed attempt to remove GitHub agent files from the repository.")
    print("The core project files remain intact.")

if __name__ == "__main__":
    main()