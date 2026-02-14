#!/usr/bin/env python3
"""
Script to remove the 'Black Hat/DEF CON Readiness' section from the README.
"""

import os
from github import Github
import configparser

def main():
    print("Removing 'Black Hat/DEF CON Readiness' section from README...")
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
        
        # Find and remove the 'Black Hat/DEF CON Readiness' section
        start_marker = "## 🏆 Black Hat/DEF CON Readiness"
        end_marker = "---"
        
        start_pos = current_content.find(start_marker)
        if start_pos != -1:
            # Find the end of the section (next header or end of document)
            # Look for the next '##' after the start position
            next_header_pos = current_content.find("## ", start_pos + len(start_marker))
            if next_header_pos == -1:  # If no more headers, find the end marker
                next_header_pos = current_content.find(end_marker, start_pos)
                if next_header_pos == -1:  # If no end marker, go to end of doc
                    next_header_pos = len(current_content)
            
            if next_header_pos != -1:
                # Keep content before the section and after the section
                updated_content = current_content[:start_pos] + current_content[next_header_pos:]
            else:
                # If we can't find a clear end, just remove from start to end of content
                updated_content = current_content[:start_pos].rstrip()
        else:
            print("Black Hat/DEF CON Readiness section not found in README")
            return
        
        # Update the README with the corrected content
        repo.update_file(
            path="README.md",
            message="Remove 'Black Hat/DEF CON Readiness' section from README",
            content=updated_content,
            sha=current_readme.sha,
            branch="main"
        )
        
        print("✅ Successfully removed 'Black Hat/DEF CON Readiness' section from README")
        
    except Exception as e:
        print(f"❌ Error updating README: {e}")

    print("\n✅ Completed removal of 'Black Hat/DEF CON Readiness' section.")

if __name__ == "__main__":
    main()