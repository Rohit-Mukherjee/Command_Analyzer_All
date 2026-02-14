#!/usr/bin/env python3
"""
Script to add documentation files to GitHub repository using the GitHub agent
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from github_agent import GitHubAgent

def main():
    # Initialize the GitHub agent
    # The agent will read the token from config.ini and repository details
    agent = GitHubAgent(config_file="config.ini")
    
    # Connect to the repository
    repo_connected = agent.connect_to_repo("Rohit-Mukherjee/Command_Analyzer_All")
    
    if not repo_connected:
        print("Failed to connect to the repository. Please check your token and repository name.")
        return
    
    # List of files to upload
    files_to_upload = [
        "Tools_Documentation.md",
        "BLACKHAT_ARSENAL_README.md"
    ]
    
    # Upload each file
    for file_path in files_to_upload:
        if os.path.exists(file_path):
            success = agent.upload_file(
                file_path=file_path,
                commit_message=f"Add {file_path} for Black Hat Arsenal documentation",
                branch="main"
            )
            if success:
                print(f"Successfully uploaded {file_path}")
            else:
                print(f"Failed to upload {file_path}")
        else:
            print(f"File does not exist: {file_path}")
    
    print("Documentation files upload process completed.")

if __name__ == "__main__":
    main()