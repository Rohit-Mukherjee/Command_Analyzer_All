#!/usr/bin/env python3
"""
Debug script to update the README file in the GitHub repository with proper URLs
"""

from github_agent import GitHubAgent
import os

def debug_update_readme():
    # Initialize the agent with your configured repository
    agent = GitHubAgent()

    # Connect to the configured repository
    if not agent.connect_to_repo():
        print("Failed to connect to the configured repository. Please check your config.ini file.")
        return

    # Define paths
    local_file_path = "/home/rohit/Downloads/ai_stuff/Github_Agent/README_CodeProjects.md"
    repo_file_path = "README.md"  # This is the path in the GitHub repo
    
    import datetime
    commit_message = f"Update README with proper repository URL and upload notice - {datetime.datetime.now()}"

    # Check if local file exists
    if not os.path.exists(local_file_path):
        print(f"Local file does not exist: {local_file_path}")
        return

    print(f"Updating {repo_file_path} in repository...")

    try:
        # Read the file content as text
        with open(local_file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        print(f"Local file length: {len(content)} characters")
        print(f"Sample content: {repr(content[80:150])}")  # Print a sample to verify content

        # Get current file to get the SHA
        try:
            current_file = agent.repo.get_contents(repo_file_path, ref="main")
            print(f"File exists, current SHA: {current_file.sha}")
            
            # Update the file
            result = agent.repo.update_file(
                path=repo_file_path,
                message=commit_message,
                content=content,
                sha=current_file.sha,
                branch="main"
            )
            print(f"Updated file: {repo_file_path}")
            print(f"New SHA: {result['commit'].sha}")
            
        except Exception as e:
            print(f"File may not exist or other error: {e}")
            # File doesn't exist, create it
            result = agent.repo.create_file(
                path=repo_file_path,
                message=commit_message,
                content=content,
                branch="main"
            )
            print(f"Created file: {repo_file_path}")
            print(f"SHA: {result['commit'].sha}")

        print("README updated successfully!")

    except Exception as e:
        print(f"Error updating README: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_update_readme()