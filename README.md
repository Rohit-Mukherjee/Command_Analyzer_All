# GitHub Agent

A Python-based GitHub agent that can automatically add files to your repository and make changes.

## Features

- Upload single or multiple files to a GitHub repository
- Update existing files in the repository
- Create new branches
- Commit changes with custom messages
- Interactive menu-driven interface

## Prerequisites

- Python 3.6 or higher
- GitHub Personal Access Token with appropriate permissions

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Get GitHub Personal Access Token

1. Go to [GitHub Settings > Developer settings > Personal access tokens](https://github.com/settings/tokens)
2. Click "Generate new token"
3. Select the scopes/permissions you want to grant to the token
4. Copy the generated token

### 3. Configuration

You can configure the agent in one of the following ways:

#### Option A: Using Environment Variable
```bash
export GITHUB_TOKEN=your_github_personal_access_token_here
```

#### Option B: Using Config File
Create a `config.ini` file in the same directory as the script with the following content:

```ini
[GITHUB]
token = your_github_personal_access_token_here
```

#### Option C: Manual Input
If no token is configured, the script will prompt you to enter your token when run.

## Usage

Run the GitHub agent:

```bash
python github_agent.py
```

Follow the interactive prompts to:
1. Enter your repository name in the format `username/repository`
2. Choose an operation:
   - Upload a single file
   - Upload multiple files
   - Commit changes to existing files
   - Create a new branch
   - Exit

## Security Note

Keep your GitHub Personal Access Token secure and never share it publicly. Store it in a secure location and do not commit it to version control.

## License

This project is open source and available under the MIT License.