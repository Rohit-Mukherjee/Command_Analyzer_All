#!/usr/bin/env python3
"""
Script to update the README file in the GitHub repository with proper URLs
"""

from github_agent import GitHubAgent
import os

def update_readme():
    # Initialize the agent with your configured repository
    agent = GitHubAgent()

    # Connect to the configured repository
    if not agent.connect_to_repo():
        print("Failed to connect to the configured repository. Please check your config.ini file.")
        return

    # Define paths
    local_file_path = "/home/rohit/Downloads/ai_stuff/Github_Agent/README_CodeProjects.md"
    repo_file_path = "README.md"  # This is the path in the GitHub repo
    commit_message = "Update README with proper repository URL and upload notice"

    # Check if local file exists
    if not os.path.exists(local_file_path):
        print(f"Local file does not exist: {local_file_path}")
        return

    print(f"Updating {repo_file_path} in repository...")

    try:
        # Read the file content as text
        with open(local_file_path, 'r', encoding='utf-8') as f:
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

        print("README updated successfully!")

    except Exception as e:
        print(f"Error updating README: {e}")

if __name__ == "__main__":
    update_readme()