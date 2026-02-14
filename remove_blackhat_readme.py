#!/usr/bin/env python3
"""
Script to remove BLACKHAT_ARSENAL_README.md from GitHub repository using the GitHub agent
"""

import sys
import os
from github import Github
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from github_agent import GitHubAgent

def main():
    # Initialize the GitHub agent
    agent = GitHubAgent(config_file="config.ini")
    
    # Connect to the repository
    repo_connected = agent.connect_to_repo("Rohit-Mukherjee/Command_Analyzer_All")
    
    if not repo_connected:
        print("Failed to connect to the repository. Please check your token and repository name.")
        return
    
    # File to delete
    file_path = "BLACKHAT_ARSENAL_README.md"
    
    # Get the file content to get its SHA
    try:
        contents = agent.repo.get_contents(file_path, ref="main")
        
        # Delete the file
        result = agent.repo.delete_file(
            path=file_path,
            message="Remove BLACKHAT_ARSENAL_README.md as requested",
            sha=contents.sha,
            branch="main"
        )
        
        if result:
            print(f"Successfully removed {file_path} from the repository")
        else:
            print(f"Failed to remove {file_path}")
            
    except Exception as e:
        print(f"Error removing file {file_path}: {e}")
    
    print("File removal process completed.")

if __name__ == "__main__":
    main()