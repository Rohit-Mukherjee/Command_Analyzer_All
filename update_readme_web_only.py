#!/usr/bin/env python3
"""
Script to update the README.md file to emphasize only the web application usage.
"""

import os
from github import Github
import configparser

def main():
    print("Updating README.md to emphasize only the web application usage...")
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
        
        # Update the "Usage" section to emphasize only the web application
        if "## 📈 Usage" in current_content:
            # Find the usage section and replace it with web-app focused instructions
            start_pos = current_content.find("## 📈 Usage")
            # Find the next section to know where the Usage section ends
            next_section_start = current_content.find("## ", start_pos + 1)
            if next_section_start == -1:  # If this is the last section
                next_section_start = len(current_content)
            
            # Create the new usage section focused only on the web app
            new_usage_section = """## 📈 Usage

### Web Application (Recommended)
For the best user experience, run the full web application:

1. **Start the web app:**
   ```bash
   streamlit run web_app.py
   ```

2. **Access the application** at `http://localhost:8501`

3. **Upload your CSV file** with a 'commandline' column

4. **Click 'Analyze'** to process your data

5. **View detailed results** including:
   - Threat detection with MITRE ATT&CK mappings
   - Behavioral anomaly detection
   - Interactive visualizations
   - Performance metrics

6. **Download the analyzed results** as CSV

### Simple Usage Instructions

After installation, you have one main option:

#### Option 1: Web Application (Only Recommended Option)
Every time you want to use the tools, you need to:

1. **Activate the virtual environment** (in a new command prompt session):
   ```
   clta_env\\\\Scripts\\\\activate.bat
   ```

2. **Run the web application**:
   ```
   streamlit run web_app.py
   ```

3. **Access the application** at `http://localhost:8501` in your browser

When you're done, you can deactivate the environment:
```
deactivate
```

The web application provides the complete user interface for all functionality including analysis, rule creation, and dashboard visualization.
"""
            
            # Reconstruct the README with the updated usage section
            updated_content = current_content[:start_pos] + new_usage_section + current_content[next_section_start:]
        else:
            print("Could not find usage section to update")
            return
        
        # Update the README with the corrected content
        repo.update_file(
            path="README.md",
            message="Update README to emphasize only the web application usage",
            content=updated_content,
            sha=current_readme.sha,
            branch="main"
        )
        
        print("✅ Successfully updated README.md to emphasize only the web application usage")
        
    except Exception as e:
        print(f"❌ Error updating README: {e}")

    print("\n✅ Completed updating README.md file.")

if __name__ == "__main__":
    main()