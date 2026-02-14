#!/usr/bin/env python3
"""
Script to perform a sanity check and remove any extraneous files from the repository.
"""

import os
from github import Github
import configparser

def main():
    print("Performing sanity check of repository files...")
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

    # List all files currently in the repository
    print("\nCurrent files in repository:")
    contents = repo.get_contents("", ref="main")
    repo_files = []
    for content_file in contents:
        print(f"  - {content_file.name}")
        repo_files.append(content_file.name)
    
    # Define the expected files for the Command Line Threat Analyzer project
    expected_project_files = {
        # Core application files
        'log_analyzer.py',
        'web_app.py',
        'rules_wizard_app.py',
        'dashboard.py',
        'behavioral_analyzer.py',
        'threat_intel.py',
        
        # Configuration and setup
        'install.bat',
        'install.sh',
        'start_web_app.sh',
        'requirements.txt',
        'requirements-dev.txt',
        'pyproject.toml',
        'setup.py',
        
        # Documentation
        'README.md',
        'demo_README.md',
        
        # Demo and test files
        'demo_environment.py',
        'check_dependencies.py',
        'simple_check.py',
        'verify_installation.py',
        'test_rules.py',
        'test_curl_rules.py',
        
        # Data files
        'rules.json',
        'session.txt',
        
        # Sample data
        'sample_data/',
        
        # Demo scenario files
        'demo_combined_scenario.csv',
        'demo_credential_theft.csv',
        'demo_data_exfiltration.csv',
        'demo_lateral_movement.csv',
        'demo_persistence_establishment.csv',
        'demo_ransomware_attack.csv',
        
        # Output files
        'Commands_analyzed.csv',
        'Commands_analyzed.xlsx',
        
        # Docker
        'Dockerfile',
    }
    
    # Additional files that were intentionally added for Windows support
    expected_windows_files = {
        'install_fixed.ps1',
        'WINDOWS_INSTALLATION.md',
        'check_installation.py',
        'start_clta.bat',
        'start_clta.ps1',
    }
    
    # Combine all expected files
    all_expected_files = expected_project_files.union(expected_windows_files)
    
    # Identify unexpected files
    unexpected_files = []
    for file in repo_files:
        if file not in all_expected_files:
            unexpected_files.append(file)
    
    if unexpected_files:
        print(f"\n⚠️  Found {len(unexpected_files)} unexpected files:")
        for file in unexpected_files:
            print(f"  - {file}")
        
        print("\nRemoving unexpected files...")
        for file in unexpected_files:
            try:
                content_file = repo.get_contents(file, ref="main")
                if isinstance(content_file, list):
                    # Handle directories if needed
                    for item in content_file:
                        repo.delete_file(item.path, 
                                       f"Remove {item.path} - unexpected file", 
                                       item.sha, 
                                       branch="main")
                        print(f"  ✅ Removed: {item.path}")
                else:
                    repo.delete_file(file, 
                                   f"Remove {file} - unexpected file", 
                                   content_file.sha, 
                                   branch="main")
                    print(f"  ✅ Removed: {file}")
            except Exception as e:
                print(f"  ⚠️  Could not remove {file}: {str(e)}")
    else:
        print("\n✅ No unexpected files found in repository.")
    
    print(f"\nRepository sanity check completed.")
    print(f"Expected files count: {len(all_expected_files)}")
    print(f"Actual files count: {len(repo_files)}")
    print(f"Unexpected files removed: {len(unexpected_files)}")

if __name__ == "__main__":
    main()