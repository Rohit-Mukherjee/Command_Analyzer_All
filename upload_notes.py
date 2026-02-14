#!/usr/bin/env python3
"""
Script to upload the SOC notes to your GitHub repository
"""

from github_agent import GitHubAgent
import os

def upload_soc_notes():
    # Initialize the agent with your configured repository
    agent = GitHubAgent()

    # Connect to the configured repository
    if not agent.connect_to_repo():
        print("Failed to connect to the configured repository. Please check your config.ini file.")
        return

    # Define paths
    local_file_path = "/home/rohit/Downloads/ai_stuff/SOC_Notes/module1.md"
    repo_file_path = "module1.md"  # This is the path in the GitHub repo
    commit_message = "Add comprehensive SOC notes on Incident Response Lifecycle"

    # Check if local file exists
    if not os.path.exists(local_file_path):
        print(f"Local file does not exist: {local_file_path}")
        return

    print(f"Uploading {local_file_path} to repository as {repo_file_path}...")

    try:
        # Read the file content
        with open(local_file_path, 'rb') as f:
            content = f.read()

        # Check if file already exists in the repo
        try:
            contents = agent.repo.get_contents(repo_file_path, ref="main")
            # File exists, update it
            result = agent.repo.update_file(
                path=repo_file_path,
                message=commit_message,
                content=content,
                sha=contents.sha,
                branch="main"
            )
            print(f"Updated file: {repo_file_path}")
        except:
            # File doesn't exist, create it
            result = agent.repo.create_file(
                path=repo_file_path,
                message=commit_message,
                content=content,
                branch="main"
            )
            print(f"Created file: {repo_file_path}")

        print("File uploaded successfully!")

    except Exception as e:
        print(f"Error uploading file: {e}")

if __name__ == "__main__":
    upload_soc_notes()