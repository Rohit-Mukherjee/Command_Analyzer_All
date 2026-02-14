#!/usr/bin/env python3
"""
Script to update Tools_Documentation.md to remove unverified performance metrics
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
    
    # Remove the performance benchmarks section
    # Find and remove the "Performance Benchmarks" section
    start_marker = "## Performance Benchmarks\n\n"
    end_marker = "\n## Security Considerations"
    
    start_pos = content.find(start_marker)
    if start_pos != -1:
        end_pos = content.find(end_marker, start_pos)
        if end_pos != -1:
            # Extract the part before the section to remove
            before_section = content[:start_pos]
            # Extract the part after the section to remove
            after_section = content[end_pos:]
            # Combine them to effectively remove the section
            updated_content = before_section + after_section
        else:
            # If we can't find the end marker, just remove from start marker to end
            updated_content = content[:start_pos]
    else:
        # If we can't find the start marker, keep the original content
        updated_content = content
    
    # Write the updated content back to the file
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(updated_content)
    
    print(f"Successfully updated {file_path} - removed unverified performance benchmarks")
    
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
        commit_message="Update Tools_Documentation.md - remove unverified performance benchmarks",
        branch="main"
    )
    
    if success:
        print(f"Successfully updated {file_path} in the repository")
    else:
        print(f"Failed to update {file_path} in the repository")

if __name__ == "__main__":
    main()