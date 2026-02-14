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

### Quick Installation (Linux/macOS)
```bash
bash quick_install_linux_macos.sh
```

### Quick Installation (Windows)
```cmd
powershell -ExecutionPolicy Bypass -File quick_install_windows.ps1
```

### Manual Installation
1. Clone the repository:
```bash
git clone https://github.com/Rohit-Mukherjee/Command_Analyzer_All.git
cd Command_Analyzer_All
```

2. Create a virtual environment:
```bash
python -m venv clta_env
source clta_env/bin/activate  # On Windows: clta_env\\Scripts\\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Web Application Interface (Recommended)
```bash
python app.py
```
Then navigate to `http://localhost:8501` in your browser.

### Command-Line Analysis
```bash
python log_analyzer.py --input logs/commands.log --output results/
```

### Interactive Rule Creation
```bash
python rules_wizard_app.py
```

### Dashboard Visualization
```bash
python dashboard.py
```

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

Run the demo environment:
```bash
python demo_environment.py
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