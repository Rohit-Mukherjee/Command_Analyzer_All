#!/usr/bin/env python3
"""
Script to upload the entire Code_Projects directory to your GitHub repository
"""

from github_agent import GitHubAgent
import os
import mimetypes

def upload_code_projects():
    # Initialize the agent with your configured repository
    agent = GitHubAgent()

    # Connect to the configured repository
    if not agent.connect_to_repo():
        print("Failed to connect to the configured repository. Please check your config.ini file.")
        return

    # Source directory
    source_dir = "/home/rohit/Downloads/ai_stuff/Code_Projects"
    
    # Check if source directory exists
    if not os.path.exists(source_dir):
        print(f"Source directory does not exist: {source_dir}")
        return

    print(f"Uploading all files from {source_dir} to repository...")

    # Walk through all files in the source directory
    for root, dirs, files in os.walk(source_dir):
        for file in files:
            # Skip __pycache__ directories and .pyc files
            if '__pycache__' in root or file.endswith('.pyc'):
                continue
                
            local_file_path = os.path.join(root, file)
            
            # Calculate the relative path from source directory to maintain folder structure
            relative_path = os.path.relpath(local_file_path, source_dir)
            
            # Create commit message
            commit_message = f"Upload {relative_path} from Code_Projects"
            
            print(f"Uploading {relative_path}...")
            
            try:
                # Read the file content
                with open(local_file_path, 'rb') as f:
                    content = f.read()

                # Determine if content is binary or text
                # For text files, we'll decode to string; for binary files, we'll keep as bytes
                mime_type, _ = mimetypes.guess_type(local_file_path)
                
                if mime_type and mime_type.startswith('text/'):
                    content_str = content.decode('utf-8')
                else:
                    # For binary files, encode to base64 string for GitHub API
                    import base64
                    content_str = base64.b64encode(content).decode('utf-8')

                # Check if file already exists in the repo
                try:
                    contents = agent.repo.get_contents(relative_path, ref="main")
                    # File exists, update it
                    result = agent.repo.update_file(
                        path=relative_path,
                        message=commit_message,
                        content=content_str,
                        sha=contents.sha,
                        branch="main"
                    )
                    print(f"Updated file: {relative_path}")
                except:
                    # File doesn't exist, create it
                    result = agent.repo.create_file(
                        path=relative_path,
                        message=commit_message,
                        content=content_str,
                        branch="main"
                    )
                    print(f"Created file: {relative_path}")

            except UnicodeDecodeError:
                # Handle binary files
                try:
                    with open(local_file_path, 'rb') as f:
                        content = f.read()
                    
                    import base64
                    content_str = base64.b64encode(content).decode('utf-8')
                    
                    # Check if file already exists in the repo
                    try:
                        contents = agent.repo.get_contents(relative_path, ref="main")
                        # File exists, update it
                        result = agent.repo.update_file(
                            path=relative_path,
                            message=commit_message,
                            content=content_str,
                            sha=contents.sha,
                            branch="main"
                        )
                        print(f"Updated binary file: {relative_path}")
                    except:
                        # File doesn't exist, create it
                        result = agent.repo.create_file(
                            path=relative_path,
                            message=commit_message,
                            content=content_str,
                            branch="main"
                        )
                        print(f"Created binary file: {relative_path}")
                        
                except Exception as e:
                    print(f"Error uploading binary file {relative_path}: {e}")
            
            except Exception as e:
                print(f"Error uploading file {relative_path}: {e}")

    print("All files uploaded successfully!")


if __name__ == "__main__":
    upload_code_projects()