# Command Line Threat Analyzer (CLTA)

## Overview

The Command Line Threat Analyzer (CLTA) is a comprehensive cybersecurity tool designed for detecting and analyzing suspicious command line activities across Windows, Linux, and macOS platforms. It serves as a command analysis tool that addresses the critical challenge faced by cybersecurity analysts: understanding the complete story of an attack when only individual detection commands are highlighted but the full narrative unfolds across multiple interconnected commands.

## Problem Statement

Modern cyberattacks involve complex command sequences that unfold over time, with attackers executing multiple commands to achieve their objectives. Current security solutions typically flag individual suspicious commands but fail to provide the complete narrative of an attack. Analysts must manually correlate multiple commands to understand the full attack story, which is time-consuming and error-prone.

CLTA solves this problem by automatically correlating related commands across time and context, providing behavioral analysis to identify attack patterns, and visualizing command sequences to reveal attack progression.

## Key Features

### Multi-Platform Threat Detection
- Comprehensive coverage across Windows, Linux, and macOS environments
- Over 240+ detection rules organized hierarchically by OS, category, and specific techniques
- Cross-platform rule sets for universal threat detection

### Hierarchical Rule Engine
- Organized by Operating System → Category → Specific Rules
- Regex-based pattern matching for flexible command detection
- Unicode-safe processing for international character support
- Dynamic severity scoring based on threat level

### Advanced Behavioral Analysis
- Anomaly detection algorithms to identify unusual command patterns
- Sequence analysis to detect multi-stage attack vectors
- Clustering algorithms to group related malicious activities
- Temporal correlation to understand attack progression

### Threat Intelligence Integration
- MITRE ATT&CK framework mappings for standardized threat categorization
- Tactic and technique identification with confidence scoring
- Integration with external threat intelligence feeds
- Detailed reporting with TTP (Tactics, Techniques, Procedures) identification

### Interactive Visualization Dashboard
- Streamlit-based interactive dashboard for analysis results
- Distribution charts showing threat patterns and frequencies
- Filtering and search capabilities for focused analysis
- Export functionality for reporting and further investigation

### Rule Creation Wizard
- Interactive GUI for creating and testing detection rules
- Visual rule creation with pattern generation
- Dry-run testing capabilities before deployment
- Real-time validation of rule effectiveness

## Installation

### Prerequisites
- **Python 3.8 or higher** (required)
- **pip** (Python package manager)

### Quick Installation

#### Windows
```powershell
# Option 1: Using the PowerShell script
powershell -ExecutionPolicy Bypass -File install_fixed_with_execution_policy.ps1

# Option 2: Manual installation
git clone https://github.com/Rohit-Mukherjee/Command_Analyzer_All.git
cd Command_Analyzer_All
python -m venv clta_env
clta_env\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

#### Linux/macOS
```bash
# Option 1: Using the install script
bash install.sh

# Option 2: Manual installation
git clone https://github.com/Rohit-Mukherjee/Command_Analyzer_All.git
cd Command_Analyzer_All
python3 -m venv clta_env
source clta_env/bin/activate
pip install -r requirements.txt
pip install -e .
```

### Required Dependencies
The following Python packages are automatically installed:
- `pandas` - Data manipulation and Excel file support
- `openpyxl` - Excel file reading/writing (required for .xlsx support)
- `streamlit` - Web application framework
- `plotly` - Interactive visualizations
- `numpy` - Numerical computing
- `scikit-learn` - Machine learning for behavioral analysis
- `requests` - HTTP requests for threat intelligence
- `PyGithub` - GitHub integration

## Usage

### 1. Web Application Interface (Recommended)
```bash
streamlit run web_app.py
```
Then navigate to `http://localhost:8501` in your browser.

**Features:**
- Upload CSV or Excel files with command line data
- Interactive threat analysis with visualizations
- MITRE ATT&CK framework integration
- Behavioral anomaly detection
- Export results to CSV/JSON/Excel

### 2. Command-Line Analysis
```bash
# Analyze a CSV file with command lines
python log_analyzer.py
```

**Configuration:** Edit `log_analyzer.py` to set input/output paths:
```python
INPUT_CSV_PATH = r"demo_ransomware_attack.csv"  # Your input file
OUTPUT_CSV_PATH = r"Commands_analyzed.csv"     # Results CSV
OUTPUT_XLSX_PATH = r"Commands_analyzed.xlsx"   # Results Excel (optional)
```

### 3. Interactive Rule Creation
```bash
streamlit run rules_wizard_app.py
```
Create and test detection rules without editing JSON manually.

### 4. Dashboard Visualization
```bash
streamlit run dashboard.py
```
View analysis results with interactive charts and filters.

### 5. Run Demo Scenarios
```bash
python demo_environment.py
```
Generates sample attack scenario data for testing.

## Supported Platforms and Rules

### Windows Detection (100+ rules)
- User and Group Management
- Scheduled Tasks and Persistence
- File Download/Upload (PowerShell, CertUtil, BITSAdmin)
- Network Discovery and Reconnaissance
- System Information Discovery
- Windows Registry Modification
- Service Manipulation
- Process Execution & Manipulation
- Firewall and Network Configuration
- UAC Bypass Techniques

### Linux Detection (80+ rules)
- User and Group Management
- Scheduled Tasks/Persistence
- File Download/Upload
- Network Discovery
- System Information Discovery
- Service Manipulation
- Firewall and Security Configuration
- Data Exfiltration/Encoding
- Credential Access/Cracking

### macOS Detection (60+ rules)
- User and Group Management
- Scheduled Tasks/Persistence
- Network Discovery
- System Information Discovery
- Launch Services/Service Manipulation
- Firewall and Security Configuration
- Credential Access/Privileged Execution

### Cross-Platform Detection (40+ rules)
- File Download/Upload
- Network Discovery
- Data Exfiltration/Encoding
- Scripting/Shells
- Container and Virtualization
- Cloud and Infrastructure

## Demo Scenarios

The tool includes comprehensive demo scenarios covering:
- Ransomware attack simulation
- Credential theft and privilege escalation
- Lateral movement techniques
- Persistence establishment methods
- Data exfiltration strategies

### Run Demo Environment
```bash
python demo_environment.py
```
This generates sample CSV files with attack scenario data for testing.

### Quick Start with Demo Data
1. Generate demo data: `python demo_environment.py`
2. Run the web app: `streamlit run web_app.py`
3. Upload one of the generated demo CSV files (e.g., `demo_ransomware_attack.csv`)
4. View the analysis results with interactive visualizations

## Troubleshooting

### Excel File Support Issues
**Problem:** Cannot read/write `.xlsx` files  
**Solution:** Ensure `openpyxl` is installed:
```bash
pip install openpyxl
```

### Streamlit App Won't Start
**Problem:** `streamlit: command not found`  
**Solution:**
```bash
# Make sure you're in the virtual environment
# On Windows:
clta_env\Scripts\activate
# On Linux/macOS:
source clta_env/bin/activate

# Then run:
streamlit run web_app.py
```

### Module Import Errors
**Problem:** `ModuleNotFoundError: No module named '...'`  
**Solution:** Install all dependencies:
```bash
pip install -r requirements.txt
pip install -e .
```

### Python Version Too Old
**Problem:** Installation fails due to Python version  
**Solution:** Upgrade to Python 3.8 or higher from [python.org](https://www.python.org/downloads/)

### PowerShell Execution Policy Error (Windows)
**Problem:** Cannot run PowerShell scripts  
**Solution:** Run PowerShell as Administrator and execute:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
Or use the bypass option:
```powershell
powershell -ExecutionPolicy Bypass -File install_fixed_with_execution_policy.ps1
```

## Architecture

### Core Components

#### Log Analyzer (`log_analyzer.py`)
The main analysis engine processes command line logs against security rules with performance metrics, threat intelligence enrichment, and behavioral analysis integration.

#### Rules Wizard (`rules_wizard_app.py`)
Interactive GUI for creating and testing detection rules with visual rule creation, pattern generation, and dry-run testing capabilities.

#### Dashboard (`dashboard.py`)
Interactive visualization dashboard for analysis results with distribution charts, filtering, and export functionality.

#### Threat Intelligence (`threat_intel.py`)
MITRE ATT&CK framework integration providing tactic and technique mapping with confidence scoring.

#### Behavioral Analysis (`behavioral_analyzer.py`)
Advanced behavioral analysis for anomaly detection using clustering algorithms and sequence analysis.

#### Demo Environment (`demo_environment.py`)
Comprehensive test scenarios including ransomware attacks, credential theft, lateral movement, persistence establishment, and data exfiltration.

## Contributing

We welcome contributions to improve the Command Line Threat Analyzer. Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to the cybersecurity community for continuous feedback and improvement suggestions
- MITRE ATT&CK framework for providing standardized threat categorization
- Open-source community for the various libraries and tools that make this project possible