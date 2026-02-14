#!/usr/bin/env python3
"""
Script to fix the rules.json file that might have encoding issues.
"""

import os
import json
from github import Github
import configparser

def main():
    print("Fixing rules.json file that might have encoding issues...")
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

    # Read the current rules.json from the local file to get the correct content
    local_rules_path = "rules.json"
    if not os.path.exists(local_rules_path):
        print(f"Local rules.json file not found: {local_rules_path}")
        return

    with open(local_rules_path, 'r', encoding='utf-8') as f:
        rules_content = f.read()

    # Validate that it's proper JSON
    try:
        json.loads(rules_content)
        print("✅ Local rules.json has valid JSON format")
    except json.JSONDecodeError as e:
        print(f"❌ Local rules.json has invalid JSON: {e}")
        return

    try:
        # Get the current rules.json file to get its SHA for the update operation
        current_rules = repo.get_contents("rules.json", ref="main")
        
        # Update the rules.json with the correct content
        repo.update_file(
            path="rules.json",
            message="Fix rules.json encoding issue",
            content=rules_content,
            sha=current_rules.sha,
            branch="main"
        )
        
        print("✅ Successfully fixed rules.json with correct encoding")
        
    except Exception as e:
        print(f"❌ Error updating rules.json: {e}")

    print("\n✅ Completed fixing rules.json file.")

if __name__ == "__main__":
    main()