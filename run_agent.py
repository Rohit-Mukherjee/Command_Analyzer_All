#!/usr/bin/env python3
"""
Simple script to run the GitHub agent with your configured repository.
"""

from github_agent import GitHubAgent

def main():
    print("GitHub Agent - Automated Repository Manager")
    print("=" * 50)
    
    # Initialize the agent - it will automatically use the repo from config if available
    agent = GitHubAgent()
    
    # Connect to the configured repository
    if not agent.connect_to_repo():
        print("Failed to connect to the configured repository. Please check your config.ini file.")
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