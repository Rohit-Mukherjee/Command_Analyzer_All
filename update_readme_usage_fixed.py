#!/usr/bin/env python3
"""
Script to update the README.md file with simplified usage instructions for Windows.
"""

import os
from github import Github
import configparser

def main():
    print("Updating README.md with simplified usage instructions for Windows...")
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

    try:
        # Get the current README.md file
        current_readme = repo.get_contents("README.md", ref="main")
        current_content = current_readme.decoded_content.decode('utf-8')
        
        # Add simplified usage instructions to the existing Usage section
        simplified_instructions = """
### Simple Usage Instructions

After installation, you have two main options:

#### Option 1: Menu Interface (Easiest)
```
start_clta.bat
```
This provides a menu with all available options.

#### Option 2: Direct Usage
Every time you want to use the tools, you need to:

1. **Activate the virtual environment** (in a new command prompt session):
   ```
   clta_env\\\\Scripts\\\\activate.bat
   ```

2. **Run the tool you want**:
   - For web interface: `streamlit run web_app.py`
   - For command line analysis: `python log_analyzer.py`
   - For rule creation: `streamlit run rules_wizard_app.py`
   - For dashboard: `streamlit run dashboard.py`

When you're done, you can deactivate the environment:
```
deactivate
```
"""
        
        # Find the "Usage" section and add the simplified instructions
        if "## 📈 Usage" in current_content:
            # Insert the simplified instructions after the main Usage heading
            pos = current_content.find("## 📈 Usage") + len("## 📈 Usage")
            updated_content = current_content[:pos] + simplified_instructions + current_content[pos:]
        else:
            # If no usage section exists, add it after the installation section
            if "### Docker Installation (Alternative)" in current_content:
                pos = current_content.find("### Docker Installation (Alternative)")
                pos = current_content.find("\n", pos)  # Find end of that section header
                simplified_section = "\n## 📈 Usage\n" + simplified_instructions
                updated_content = current_content[:pos] + simplified_section + current_content[pos:]
            else:
                # Append to the end of the file
                simplified_section = "\n## 📈 Usage\n" + simplified_instructions
                updated_content = current_content + simplified_section
        
        # Update the README with the corrected content
        repo.update_file(
            path="README.md",
            message="Update README with simplified usage instructions for Windows",
            content=updated_content,
            sha=current_readme.sha,
            branch="main"
        )
        
        print("✅ Successfully updated README.md with simplified usage instructions")
        
    except Exception as e:
        print(f"❌ Error updating README: {e}")

    print("\n✅ Completed updating README.md file.")

if __name__ == "__main__":
    main()