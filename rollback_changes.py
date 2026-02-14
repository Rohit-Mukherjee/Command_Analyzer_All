#!/usr/bin/env python3
"""
Script to rollback the changes made to the repository by restoring previous versions of files.
"""

import os
from github import Github
import configparser

def main():
    print("Rolling back changes to the repository...")
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

    # Get the repository's git commits to find the previous state
    try:
        commits = repo.get_commits()
        if commits.totalCount < 2:
            print("Not enough commits to rollback to a previous state.")
            return
            
        # Get the previous commit (second most recent)
        prev_commit = commits[1]
        print(f"Found previous commit: {prev_commit.sha[:8]}")
        
        # Get the file contents from the previous commit
        files_to_restore = ["README.md", "install.bat"]
        
        for filename in files_to_restore:
            try:
                # Get the file content from the previous commit
                # We'll need to get the tree from the previous commit
                print(f"Restoring {filename} to previous version...")
                
                # Get the file content from the previous commit
                prev_file_content = repo.get_contents(filename, ref=prev_commit.sha)
                
                # Get the current file to get its SHA for the update operation
                try:
                    current_file = repo.get_contents(filename, ref="main")
                    current_sha = current_file.sha
                    
                    # Update the file with the previous content
                    repo.update_file(
                        path=filename,
                        message=f"Revert {filename} to previous version",
                        content=prev_file_content.decoded_content.decode('utf-8'),
                        sha=current_sha,
                        branch="main"
                    )
                    
                    print(f"✅ Restored {filename} to previous version")
                except:
                    # If file doesn't exist in current branch, create it
                    repo.create_file(
                        path=filename,
                        message=f"Restore {filename} from previous commit",
                        content=prev_file_content.decoded_content.decode('utf-8'),
                        branch="main"
                    )
                    print(f"✅ Created {filename} from previous version")
                    
            except Exception as e:
                print(f"⚠️ Could not restore {filename}: {str(e)}")
        
        print("\n✅ Attempted to rollback changes to the repository.")
        print("Some files have been restored to their previous versions.")
        
    except Exception as e:
        print(f"❌ Error getting commits: {e}")
        print("Trying alternative approach...")

        # Alternative: Remove the newly added files only
        files_to_remove = [
            "WINDOWS_INSTALLATION.md",
            "check_installation.py", 
            "install_fixed.ps1",
            "start_clta.bat",
            "start_clta.ps1"
        ]
        
        for file_path in files_to_remove:
            try:
                contents = repo.get_contents(file_path, ref="main")
                repo.delete_file(file_path, 
                               f"Remove {file_path} - rollback", 
                               contents.sha, 
                               branch="main")
                print(f"✅ Removed: {file_path}")
            except Exception as e:
                print(f"⚠️  Could not remove {file_path}: {str(e)} (may not exist)")

if __name__ == "__main__":
    main()