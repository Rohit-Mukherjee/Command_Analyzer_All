#!/usr/bin/env python3
"""
Script to fix the pyproject.toml file that has TOML syntax errors.
"""

import os
from github import Github
import configparser

def main():
    print("Fixing pyproject.toml file with TOML syntax errors...")
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

    # Define the correct pyproject.toml content
    correct_pyproject_content = """[build-system]
requires = ["setuptools>=45", "wheel", "setuptools_scm[toml]>=6.2"]
build-backend = "setuptools.build_meta"

[project]
name = "command-line-threat-analyzer"
version = "1.0.0"
authors = [
    {name = "Rohit", email = "your-email@example.com"},
]
description = "A comprehensive cybersecurity tool for detecting and analyzing suspicious command line activities across Windows, Linux, and macOS platforms."
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.8"
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "Intended Audience :: Information Technology",
    "Intended Audience :: System Administrators",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Topic :: Security",
    "Topic :: System :: Logging",
    "Topic :: Utilities",
]
dependencies = [
    "pandas>=1.5.0",
    "streamlit>=1.28.0",
    "plotly>=5.15.0",
    "scikit-learn>=1.3.0",
    "numpy>=1.24.0",
    "requests>=2.31.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=6.0",
    "black",
    "flake8",
    "mypy",
]

[project.urls]
Homepage = "https://github.com/yourusername/command-line-threat-analyzer"
Repository = "https://github.com/yourusername/command-line-threat-analyzer"
Issues = "https://github.com/yourusername/command-line-threat-analyzer/issues"

[project.scripts]
clta-analyze = "log_analyzer:main"
"""

    try:
        # Get the current pyproject.toml file to get its SHA for the update operation
        current_pyproject = repo.get_contents("pyproject.toml", ref="main")
        
        # Update the pyproject.toml with the correct content
        repo.update_file(
            path="pyproject.toml",
            message="Fix TOML syntax error in pyproject.toml",
            content=correct_pyproject_content,
            sha=current_pyproject.sha,
            branch="main"
        )
        
        print("✅ Successfully fixed pyproject.toml with correct TOML syntax")
        
    except Exception as e:
        print(f"❌ Error updating pyproject.toml: {e}")

    print("\n✅ Completed fixing pyproject.toml file.")

if __name__ == "__main__":
    main()