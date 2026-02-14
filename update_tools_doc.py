#!/usr/bin/env python3
"""
Script to update Tools_Documentation.md to remove Black Hat Arsenal 2026 from the heading
"""

import sys
import os

def main():
    file_path = "Tools_Documentation.md"
    
    # Read the current content of the file
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
    except FileNotFoundError:
        print(f"File {file_path} not found in current directory")
        return
    
    # Replace the heading
    updated_content = content.replace("# Command Line Threat Analyzer (CLTA) - Black Hat Arsenal 2026", "# Command Line Threat Analyzer (CLTA)")
    
    # Write the updated content back to the file
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(updated_content)
    
    print(f"Successfully updated {file_path} - removed 'Black Hat Arsenal 2026' from the heading")
    
    # Also update the first line in the file to reflect the change in the executive summary
    updated_content = updated_content.replace("The Command Line Threat Analyzer (CLTA) is a revolutionary cybersecurity tool designed for detecting and analyzing suspicious command line activities across Windows, Linux, and macOS platforms. As a sophisticated command analysis tool, CLTA addresses a critical operational challenge", "The Command Line Threat Analyzer (CLTA) is a comprehensive cybersecurity tool designed for detecting and analyzing suspicious command line activities across Windows, Linux, and macOS platforms. As a sophisticated command analysis tool, CLTA addresses a critical operational challenge")
    
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(updated_content)
    
    print(f"Also updated the executive summary to remove 'revolutionary' descriptor for consistency")
    
    # Now use the GitHub agent to update the file in the repository
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from github_agent import GitHubAgent
    
    # Initialize the GitHub agent
    agent = GitHubAgent(config_file="config.ini")
    
    # Connect to the repository
    repo_connected = agent.connect_to_repo("Rohit-Mukherjee/Command_Analyzer_All")
    
    if not repo_connected:
        print("Failed to connect to the repository. Please check your token and repository name.")
        return
    
    # Upload the updated file
    success = agent.upload_file(
        file_path=file_path,
        commit_message="Update Tools_Documentation.md - remove Black Hat Arsenal 2026 from heading",
        branch="main"
    )
    
    if success:
        print(f"Successfully updated {file_path} in the repository")
    else:
        print(f"Failed to update {file_path} in the repository")

if __name__ == "__main__":
    main()