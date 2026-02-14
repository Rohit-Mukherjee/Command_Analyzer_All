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
        
        # Find the "Usage" section and add simplified instructions
        usage_section_start = current_content.find("## 📈 Usage")
        if usage_section_start != -1:
            # Find the next section to know where the Usage section ends
            next_section_start = current_content.find("## ", usage_section_start + 1)
            if next_section_start == -1:  # If this is the last section
                next_section_start = len(current_content)
            
            # Extract the current usage section
            current_usage_section = current_content[usage_section_start:next_section_start]
            
            # Create the simplified usage instructions
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
            
            # Insert the simplified instructions at the beginning of the Usage section
            new_usage_section = current_usage_section[:current_usage_section.find("\n", current_usage_section.find("## 📈 Usage")) + 1] + simplified_instructions + current_usage_section[current_usage_section.find("\n", current_usage_section.find("## 📈 Usage")) + 1:]
            
            # Reconstruct the README with the updated usage section
            updated_content = current_content[:usage_section_start] + new_usage_section + current_content[next_section_start:]
        else:
            # If no usage section exists, add it after the installation section
            install_section_end = current_content.find("### Docker Installation (Alternative)")
            if install_section_end != -1:
                install_section_end = current_content.find("\n", current_content.find("### Docker Installation (Alternative)") + 1)
                simplified_instructions = """
## 📈 Usage

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
                updated_content = current_content[:install_section_end] + simplified_instructions + current_content[install_section_end:]
            else:
                print("Could not find appropriate place to add usage instructions")
                return
        
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