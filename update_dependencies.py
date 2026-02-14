#!/usr/bin/env python3
"""
Script to update the pyproject.toml file to include openpyxl for Excel export functionality.
"""

import os
from github import Github
import configparser

def main():
    print("Updating pyproject.toml to include openpyxl for Excel export...")
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

    # Define the correct pyproject.toml content with openpyxl added
    updated_pyproject_content = """[build-system]
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
    "openpyxl>=3.0.0",
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
        
        # Update the pyproject.toml with the correct content that includes openpyxl
        repo.update_file(
            path="pyproject.toml",
            message="Add openpyxl to dependencies for Excel export functionality",
            content=updated_pyproject_content,
            sha=current_pyproject.sha,
            branch="main"
        )
        
        print("✅ Successfully updated pyproject.toml with openpyxl dependency")
        
    except Exception as e:
        print(f"❌ Error updating pyproject.toml: {e}")

    # Also update requirements.txt to include the proper dependencies
    requirements_content = """pandas>=1.5.0
streamlit>=1.28.0
plotly>=5.15.0
scikit-learn>=1.3.0
numpy>=1.24.0
requests>=2.31.0
openpyxl>=3.0.0
"""
    
    try:
        # Get the current requirements.txt file to get its SHA for the update operation
        current_requirements = repo.get_contents("requirements.txt", ref="main")
        
        # Update the requirements.txt with the proper content
        repo.update_file(
            path="requirements.txt",
            message="Update requirements.txt with proper dependencies including openpyxl",
            content=requirements_content,
            sha=current_requirements.sha,
            branch="main"
        )
        
        print("✅ Successfully updated requirements.txt with proper dependencies")
        
    except Exception as e:
        print(f"❌ Error updating requirements.txt: {e}")

    print("\n✅ Completed updating dependency files to include openpyxl.")

if __name__ == "__main__":
    main()