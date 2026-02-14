import os
import json
import requests
from github import Github
from datetime import datetime
import configparser
import getpass


class GitHubAgent:
    """
    A GitHub agent that can automatically add files to your repository and make changes.
    """

    def __init__(self, token=None, repo_name=None, config_file="config.ini"):
        """
        Initialize the GitHub agent.

        Args:
            token (str): GitHub personal access token
            repo_name (str): Name of the repository in format 'username/repo'
            config_file (str): Path to the config file
        """
        self.config_file = config_file
        self.token = token or self._get_token()
        self.github = Github(self.token)
        self.repo_name = repo_name or self._get_repo_details()
        self.repo = None

    def _get_repo_details(self):
        """
        Get repository details from config file.
        """
        if os.path.exists(self.config_file):
            config = configparser.ConfigParser()
            config.read(self.config_file)
            if 'REPOSITORY' in config:
                if 'full_name' in config['REPOSITORY'] and config['REPOSITORY']['full_name'].strip():
                    return config['REPOSITORY']['full_name']
                elif ('owner' in config['REPOSITORY'] and 'name' in config['REPOSITORY'] and
                      config['REPOSITORY']['owner'].strip() and config['REPOSITORY']['name'].strip()):
                    return f"{config['REPOSITORY']['owner'].strip()}/{config['REPOSITORY']['name'].strip()}"

        return None
        
    def _get_token(self):
        """
        Get the GitHub token from config file or environment variable.
        """
        # Try to get token from config file
        if os.path.exists(self.config_file):
            config = configparser.ConfigParser()
            config.read(self.config_file)
            if 'GITHUB' in config and 'token' in config['GITHUB']:
                return config['GITHUB']['token']
        
        # Try to get token from environment variable
        token = os.environ.get('GITHUB_TOKEN')
        if token:
            return token
            
        # Ask user for token
        print("GitHub token not found.")
        print("Please provide your GitHub Personal Access Token.")
        print("You can create one at: https://github.com/settings/tokens")
        return getpass.getpass("Enter your GitHub token: ")
    
    def connect_to_repo(self, repo_name=None):
        """
        Connect to a GitHub repository.

        Args:
            repo_name (str): Name of the repository in format 'username/repo'
        """
        # Use the provided repo_name or fall back to the one from config
        repo_name = repo_name or self.repo_name

        if not repo_name:
            print("No repository name provided. Please provide a repository name in format 'username/repo'.")
            return False

        try:
            self.repo = self.github.get_repo(repo_name)
            print(f"Successfully connected to repository: {repo_name}")
            return True
        except Exception as e:
            print(f"Error connecting to repository: {e}")
            return False
    
    def upload_file(self, file_path, commit_message=None, branch="main"):
        """
        Upload a file to the repository.
        
        Args:
            file_path (str): Path to the local file to upload
            commit_message (str): Commit message for the change
            branch (str): Branch to commit to (default: main)
        """
        if not self.repo:
            print("No repository connected. Please connect to a repository first.")
            return False
            
        if not os.path.exists(file_path):
            print(f"File does not exist: {file_path}")
            return False
            
        # Read the file content
        with open(file_path, 'rb') as f:
            content = f.read()
            
        # Create commit message if not provided
        if not commit_message:
            commit_message = f"Add {os.path.basename(file_path)} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        try:
            # Check if file already exists in the repo
            try:
                contents = self.repo.get_contents(file_path, ref=branch)
                # File exists, update it
                self.repo.update_file(
                    path=file_path,
                    message=commit_message,
                    content=content,
                    sha=contents.sha,
                    branch=branch
                )
                print(f"Updated file: {file_path}")
            except:
                # File doesn't exist, create it
                self.repo.create_file(
                    path=file_path,
                    message=commit_message,
                    content=content,
                    branch=branch
                )
                print(f"Uploaded file: {file_path}")
                
            return True
        except Exception as e:
            print(f"Error uploading file: {e}")
            return False
    
    def create_or_update_multiple_files(self, file_list, commit_message=None, branch="main"):
        """
        Upload multiple files to the repository.
        
        Args:
            file_list (list): List of file paths to upload
            commit_message (str): Commit message for the changes
            branch (str): Branch to commit to (default: main)
        """
        if not self.repo:
            print("No repository connected. Please connect to a repository first.")
            return False
            
        if not commit_message:
            commit_message = f"Update multiple files - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        try:
            # Prepare the content for all files
            files_data = []
            for file_path in file_list:
                if not os.path.exists(file_path):
                    print(f"File does not exist: {file_path}")
                    continue
                    
                with open(file_path, 'rb') as f:
                    content = f.read()
                    
                # Check if file already exists
                try:
                    contents = self.repo.get_contents(file_path, ref=branch)
                    # File exists, prepare for update
                    files_data.append({
                        'path': file_path,
                        'content': content.decode('utf-8'),
                        'sha': contents.sha,
                        'action': 'update'
                    })
                except:
                    # File doesn't exist, prepare for creation
                    files_data.append({
                        'path': file_path,
                        'content': content.decode('utf-8'),
                        'action': 'create'
                    })
            
            # Process each file
            for file_data in files_data:
                if file_data['action'] == 'update':
                    self.repo.update_file(
                        path=file_data['path'],
                        message=commit_message,
                        content=file_data['content'],
                        sha=file_data['sha'],
                        branch=branch
                    )
                    print(f"Updated file: {file_data['path']}")
                else:
                    self.repo.create_file(
                        path=file_data['path'],
                        message=commit_message,
                        content=file_data['content'],
                        branch=branch
                    )
                    print(f"Created file: {file_data['path']}")
                    
            return True
        except Exception as e:
            print(f"Error uploading multiple files: {e}")
            return False
    
    def create_branch(self, branch_name, base_branch="main"):
        """
        Create a new branch in the repository.
        
        Args:
            branch_name (str): Name of the new branch
            base_branch (str): Base branch to create from (default: main)
        """
        if not self.repo:
            print("No repository connected. Please connect to a repository first.")
            return False
            
        try:
            sb = self.repo.get_branch(base_branch)
            self.repo.create_git_ref(ref=f'refs/heads/{branch_name}', sha=sb.commit.sha)
            print(f"Created branch: {branch_name}")
            return True
        except Exception as e:
            print(f"Error creating branch: {e}")
            return False
    
    def commit_changes(self, file_paths, commit_message, branch="main"):
        """
        Commit changes to specified files.
        
        Args:
            file_paths (list or str): Single file path or list of file paths to commit
            commit_message (str): Commit message
            branch (str): Branch to commit to (default: main)
        """
        if isinstance(file_paths, str):
            file_paths = [file_paths]
            
        return self.create_or_update_multiple_files(file_paths, commit_message, branch)
    
    def get_repo_info(self):
        """
        Get information about the connected repository.
        """
        if not self.repo:
            print("No repository connected.")
            return None
            
        info = {
            'name': self.repo.name,
            'full_name': self.repo.full_name,
            'description': self.repo.description,
            'html_url': self.repo.html_url,
            'created_at': self.repo.created_at,
            'updated_at': self.repo.updated_at,
            'size': self.repo.size,
            'forks_count': self.repo.forks_count,
            'stargazers_count': self.repo.stargazers_count
        }
        return info


def main():
    """
    Main function to demonstrate the GitHub agent capabilities.
    """
    print("GitHub Agent - Automated Repository Manager")
    print("=" * 50)

    # Initialize the agent
    agent = GitHubAgent()

    # Try to connect to the configured repository, or ask user for one
    if agent.repo_name:
        print(f"Repository configured in config file: {agent.repo_name}")
        use_configured = input(f"Do you want to use this repository? (y/n, press Enter for yes): ").strip().lower()
        if use_configured == '' or use_configured.startswith('y'):
            repo_name = agent.repo_name
        else:
            repo_name = input("Enter the repository name (format: username/repository): ").strip()
    else:
        # Get repository name from user
        repo_name = input("Enter the repository name (format: username/repository): ").strip()

    # Connect to the repository
    if not agent.connect_to_repo(repo_name):
        print("Failed to connect to the repository. Exiting.")
        return
    
    # Show repository info
    repo_info = agent.get_repo_info()
    if repo_info:
        print(f"\nConnected to repository: {repo_info['full_name']}")
        print(f"Description: {repo_info['description']}")
        print(f"URL: {repo_info['html_url']}")
    
    # Menu for operations
    while True:
        print("\nSelect an operation:")
        print("1. Upload a single file")
        print("2. Upload multiple files")
        print("3. Commit changes to existing files")
        print("4. Create a new branch")
        print("5. Exit")
        
        choice = input("Enter your choice (1-5): ").strip()
        
        if choice == "1":
            file_path = input("Enter the path to the file you want to upload: ").strip()
            commit_msg = input("Enter commit message (press Enter for auto-generated): ").strip()
            branch = input("Enter branch name (press Enter for 'main'): ").strip() or "main"
            
            agent.upload_file(file_path, commit_msg or None, branch)
            
        elif choice == "2":
            print("Enter file paths one per line. Press Enter on empty line to finish:")
            file_paths = []
            while True:
                path = input().strip()
                if not path:
                    break
                file_paths.append(path)
            
            if file_paths:
                commit_msg = input("Enter commit message (press Enter for auto-generated): ").strip()
                branch = input("Enter branch name (press Enter for 'main'): ").strip() or "main"
                
                agent.create_or_update_multiple_files(file_paths, commit_msg or None, branch)
            else:
                print("No files provided.")
                
        elif choice == "3":
            file_path = input("Enter the path(s) to the file(s) you want to commit (separate with commas for multiple): ").strip()
            file_paths = [f.strip() for f in file_path.split(',')]
            commit_msg = input("Enter commit message: ").strip()
            branch = input("Enter branch name (press Enter for 'main'): ").strip() or "main"
            
            agent.commit_changes(file_paths, commit_msg, branch)
            
        elif choice == "4":
            branch_name = input("Enter the name for the new branch: ").strip()
            base_branch = input("Enter the base branch name (press Enter for 'main'): ").strip() or "main"
            
            agent.create_branch(branch_name, base_branch)
            
        elif choice == "5":
            print("Exiting GitHub Agent. Goodbye!")
            break
            
        else:
            print("Invalid choice. Please select a valid option.")


if __name__ == "__main__":
    main()