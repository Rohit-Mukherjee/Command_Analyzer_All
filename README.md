# Command Line Threat Analyzer

A comprehensive cybersecurity tool for detecting and analyzing suspicious command line activities across Windows, Linux, and macOS platforms.

## 🚀 Features

### Core Analysis
- **Multi-Platform Support**: Detects threats across Windows, Linux, and macOS
- **Hierarchical Rule Engine**: Organized by OS → Category → Rules
- **Regex-Based Matching**: Flexible pattern matching for command detection
- **Unicode Safe**: Proper handling of special characters for Excel compatibility

### Enhanced Capabilities
- **Performance Metrics**: Detailed timing and efficiency measurements
- **Threat Intelligence Integration**: MITRE ATT&CK framework mappings
- **Behavioral Analysis**: Anomaly detection and sequence analysis
- **Visual Dashboard**: Interactive Streamlit-based visualization
- **Comprehensive Reporting**: Detailed analysis reports with TTP identification

## 📊 Components

### 1. Log Analyzer (`log_analyzer.py`)
Main analysis engine that processes command line logs against security rules.

**Key Features:**
- Performance metrics and benchmarking
- Threat intelligence enrichment
- Behavioral analysis integration
- Excel-safe CSV output

### 2. Rules Wizard (`rules_wizard_app.py`)
Interactive GUI for creating and testing detection rules.

**Key Features:**
- Visual rule creation interface
- Pattern generation from examples
- Dry-run testing against datasets
- Automatic backup of rules

### 3. Dashboard (`dashboard.py`)
Interactive visualization dashboard for analysis results.

**Key Features:**
- Distribution charts and metrics
- Filtering and search capabilities
- Export functionality
- Detailed results view

### 4. Threat Intelligence (`threat_intel.py`)
MITRE ATT&CK framework integration for enhanced detection.

**Key Features:**
- Tactic and technique mapping
- Confidence scoring
- Reference links to MITRE documentation

### 5. Behavioral Analysis (`behavioral_analyzer.py`)
Advanced behavioral analysis for anomaly detection.

**Key Features:**
- Anomaly detection algorithms
- Sequence analysis for attack chains
- Feature extraction and clustering
- Behavioral flagging

### 6. Demo Environment (`demo_environment.py`)
Comprehensive test scenarios for validation.

**Scenarios:**
- Ransomware Attack
- Credential Theft
- Lateral Movement
- Persistence Establishment
- Data Exfiltration

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Quick Installation (Recommended)

#### On Linux/macOS:
```bash
# Clone the repository
git clone https://github.com/Rohit-Mukherjee/Command_Analyzer_All
cd Command_Analyzer_All

# Make the install script executable and run it
chmod +x install.sh
./install.sh
```

#### On Windows:
```cmd
# Clone the repository
git clone https://github.com/Rohit-Mukherjee/Command_Analyzer_All
cd Command_Analyzer_All

# Run the installation script
install.bat
```

**Note for Windows Users:** If the batch script doesn't work, you can also use the PowerShell script:
```powershell
# Run the PowerShell installation script
.\install_fixed.ps1
```

For more detailed Windows installation instructions, see [WINDOWS_INSTALLATION.md](WINDOWS_INSTALLATION.md).

### Manual Installation

If you prefer to install manually:

```bash
# Clone the repository
git clone https://github.com/Rohit-Mukherjee/Command_Analyzer_All
cd Command_Analyzer_All

# (Optional but recommended) Create a virtual environment
python -m venv clta_env
source clta_env/bin/activate  # On Linux/macOS
# OR
clta_env\Scripts\activate     # On Windows

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Verify Installation
```bash
# Check dependencies
python simple_check.py

# Test the analyzer
python log_analyzer.py
```

### Running the Applications

After installation, you can run:

```bash
# Command line analyzer
python log_analyzer.py

# Web application (recommended)
streamlit run web_app.py

# Rules wizard
streamlit run rules_wizard_app.py

# Dashboard
streamlit run dashboard.py

# Or use the start script
./start_web_app.sh  # On Linux/macOS
# OR
bash start_web_app.sh  # On Windows with Git Bash
```

### Docker Installation (Alternative)

For users who prefer containerization:

```bash
# Clone the repository
git clone https://github.com/Rohit-Mukherjee/Command_Analyzer_All
cd Command_Analyzer_All

# Build the Docker image
docker build -t command-line-threat-analyzer .

# Run the application
docker run -p 8501:8501 command-line-threat-analyzer

# Or run with access to local files
docker run -p 8501:8501 -v $(pwd):/app/data command-line-threat-analyzer
```

Access the application at `http://localhost:8501`

## 📈 Usage

### Basic Analysis
1. Prepare your command line data in CSV format with a `commandline` column
2. Update `INPUT_CSV_PATH` in `log_analyzer.py`
3. Run the analyzer: `python log_analyzer.py`
4. Review results in the generated CSV and XLSX files

### Interactive Rule Creation
1. Run the rules wizard: `streamlit run rules_wizard_app.py`
2. Create new detection rules using the GUI
3. Test rules against your data
4. Export updated rules

### Visualization
1. Run the dashboard: `streamlit run dashboard.py`
2. Upload your analysis results
3. Explore visualizations and drill down into details

### Web Application (Recommended)
For the best user experience, run the full web application:

1. **Start the web app:**
   ```bash
   ./start_web_app.sh
   ```
   or
   ```bash
   python -m streamlit run web_app.py
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

## 🎯 Detection Capabilities

### Windows (100+ rules)
- **User and Group Management**: Account creation/deletion, group membership changes
- **Scheduled Tasks**: Task creation, modification, and execution
- **File Download and Upload**: PowerShell, CertUtil, BITSAdmin, curl, wget
- **Network Discovery**: Traceroute, ipconfig, nbtstat, arp, netsh
- **System Information Discovery**: Systeminfo, wmic, driverquery, tasklist
- **Windows Registry Modification**: Run keys, autoruns, policy checks
- **Service Manipulation**: Service creation, deletion, configuration
- **Process Execution & Manipulation**: DLL execution, HTA, WSH, process hollowing
- **Firewall and Network Configuration**: Netsh, port proxy, interface config
- **Account Policy Inspection**: Net accounts, password policies
- **Share and Session Enumeration**: Net share, session, use, view
- **PowerShell Execution Policy / Behavior**: Bypass, encoded commands, IEX
- **Defender and Security Evasion**: Real-time monitoring, exclusions, service manipulation
- **Password Dumping / Mimikatz**: Credential dumping tools and techniques
- **Browser Download Activity**: Chrome, Edge, Firefox command-line usage
- **Volume Shadow Copy Manipulation**: VSSAdmin, WMIC, WBAdmin, DiskShadow
- **WSCRIPT / CSCRIPT Suspicious Usage**: Script host abuse
- **Other Suspicious / Malicious Patterns**: Event log clearing, USN journal deletion
- **Lateral Movement / Impacket**: PsExec, WMIExec, SMBExec, secretsdump
- **Memory Injection and Process Hollowing**: DLL injection, mavinject
- **UAC Bypass Techniques**: FodHelper, ComputerDefaults, EventVWR

### Linux (80+ rules)
- **User and Group Management**: Useradd, userdel, usermod, passwd, su
- **Scheduled Tasks / Persistence**: Cron, at, systemd timers, init scripts
- **File Download and Upload**: SCP, rsync, netcat, dd, curl, wget
- **Network Discovery**: IP route, ifconfig, ss, lsof, dig, traceroute, nmap
- **System Information Discovery**: Uname, lsb_release, ps, id, cat /etc/*
- **Service Manipulation**: Systemctl, service, update-rc.d, supervisorctl
- **Firewall and Security Configuration**: Iptables, nftables, ufw, SELinux
- **Data Exfiltration / Encoding**: Tar, zip, 7z, base64, gpg, openssl
- **Credential Access / Cracking**: John, hashcat, hydra, medusa, cewl
- **Scripting / Suspicious Execution**: Pipelined scripts, screen, tmux, nohup
- **Kernel and Driver Manipulation**: Insmod, rmmod, modprobe, DKMS
- **Log Manipulation**: Log deletion, truncation, redirection

### macOS (60+ rules)
- **User and Group Management**: dscl, sysadminctl, dsmemberutil
- **Scheduled Tasks / Persistence**: Launchctl, crontab, pmset
- **Network Discovery**: Ifconfig, scutil, networksetup, lsof
- **System Information Discovery**: System_profiler, sw_vers, ioreg, csrutil
- **Launch Services / Service Manipulation**: Launchctl, brew services
- **Firewall and Security Configuration**: Socketfilterfw, pfctl, spctl, tccutil
- **Credential Access / Privileged Execution**: Security, osascript, sudo
- **Scripting / Suspicious Execution**: Curl piped scripts, plutil, defaults
- **macOS Specific Persistence**: LaunchAgents, LaunchDaemons, Preferences

### Cross-Platform (40+ rules)
- **File Download and Upload**: curl, wget, fetch, aria2c, axel
- **Network Discovery**: Ping, nslookup, netstat, arp, whoami, id
- **Data Exfiltration / Encoding**: Base64, tar, zip, gpg, openssl
- **Scripting / Shells**: Python, Perl, Ruby, Node.js, PHP, Java
- **Container and Virtualization**: Docker, Kubernetes, Podman, LXC
- **Cloud and Infrastructure**: AWS CLI, Google Cloud SDK, Azure CLI, Terraform

## 📊 Enhanced Features

### Advanced Analysis
- **Configurable Analysis Parameters**: Toggle threat intelligence and behavioral analysis
- **Dynamic Severity Scoring**: Automatic threat level assignment (Low to Critical)
- **Timeline Visualization**: Shows threat activity over time
- **Enhanced Filtering**: Multi-dimensional filtering by OS, Category, Severity, Anomalies

### User Experience
- **Search Functionality**: Search within command lines
- **Multiple Export Formats**: CSV, JSON, and Excel with summary sheets
- **Color-Coded Severity Indicators**: Visual threat level representation
- **Real-time Metrics**: Live updates of analysis results

### Technical Improvements
- **Robust CSV Parsing**: Handles malformed CSV files gracefully
- **Case-Insensitive Column Detection**: Works with 'commandline' or 'commandlines' in any case
- **Memory-Efficient Processing**: Optimized for large files
- **Error Resilience**: Continues processing even with problematic data

## 🔍 Threat Intelligence Mappings

The analyzer integrates with MITRE ATT&CK framework including:
- Tactic identification (Persistence, Execution, Credential Access, etc.)
- Technique mapping (T1136.001, T1059.001, etc.)
- Confidence scoring
- Reference documentation

## 📊 Behavioral Analysis

Advanced behavioral analysis features:
- Anomaly detection using clustering algorithms
- Sequence analysis for attack chain identification
- Feature extraction for command complexity
- Behavioral flagging for suspicious patterns

## 🧪 Demo Scenarios

The included demo environment provides realistic attack scenarios:
- **Ransomware Attack**: Full lifecycle simulation
- **Credential Theft**: Multiple harvesting techniques
- **Lateral Movement**: Network traversal methods
- **Persistence Establishment**: Access maintenance
- **Data Exfiltration**: Information theft techniques

## 📋 Requirements

- Python 3.8+
- pandas
- streamlit
- plotly
- scikit-learn
- numpy

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---
*Command Line Threat Analyzer - Advanced cybersecurity analysis for modern threats*