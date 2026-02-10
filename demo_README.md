
# Command Line Analyzer - Demo Scenarios

This demo environment contains several realistic attack scenarios to test the command line analyzer's detection capabilities.

## Scenarios Included

### 1. Ransomware Attack (`demo_ransomware_attack.csv`)
This scenario simulates a ransomware attack lifecycle:
- **Reconnaissance**: System and network information gathering
- **Privilege Escalation**: Preparation for elevated access
- **Persistence**: Establishing backdoors and auto-start mechanisms
- **Defense Evasion**: Disabling security tools and clearing logs
- **Payload Delivery**: Downloading and executing encryption tools
- **Impact**: Encrypting files and demanding ransom

### 2. Credential Theft (`demo_credential_theft.csv`)
This scenario demonstrates credential harvesting techniques:
- **Reconnaissance**: Identifying users and processes
- **LSASS Dumps**: Extracting credentials from memory
- **Registry Access**: Retrieving stored passwords
- **Browser Theft**: Harvesting browser credentials
- **Network Credentials**: Extracting WiFi and domain credentials

### 3. Lateral Movement (`demo_lateral_movement.csv`)
This scenario shows techniques for moving through a network:
- **Network Reconnaissance**: Discovering hosts and services
- **PsExec Usage**: Remote command execution
- **WMI Attacks**: Using WMI for remote operations
- **Scheduled Tasks**: Leveraging scheduled tasks for movement
- **PowerShell Remoting**: Using PSRemoting for access
- **Pass-the-Hash**: Using credential hashes for authentication

### 4. Persistence Establishment (`demo_persistence_establishment.csv`)
This scenario demonstrates maintaining access:
- **Backdoor Users**: Creating new user accounts
- **Registry Persistence**: Using Run keys and other registry locations
- **Scheduled Tasks**: Creating persistent scheduled tasks
- **Services**: Installing malicious services
- **WMI Events**: Using WMI event subscriptions
- **Startup Folders**: Using startup folders for persistence

### 5. Data Exfiltration (`demo_data_exfiltration.csv`)
This scenario shows data theft techniques:
- **Data Discovery**: Finding sensitive files
- **Database Access**: Querying databases for sensitive information
- **Archiving**: Compressing sensitive data
- **Encoding**: Encoding data to evade detection
- **Transfer Methods**: Various exfiltration techniques
- **Steganography**: Hiding data in images

## How to Use

1. Run the analyzer on individual scenarios:
   ```bash
   python log_analyzer.py  # Modify INPUT_CSV_PATH to point to specific scenario
   ```

2. Or analyze the combined dataset:
   ```bash
   # Modify INPUT_CSV_PATH in log_analyzer.py to "demo_combined_scenario.csv"
   python log_analyzer.py
   ```

3. View results in the generated CSV and XLSX files

4. Use the dashboard to visualize findings:
   ```bash
   python -m streamlit run dashboard.py
   ```

## Expected Detection Rates

- Ransomware Attack: High (90-100% detection rate expected)
- Credential Theft: Very High (95-100% detection rate expected)
- Lateral Movement: High (85-95% detection rate expected)
- Persistence Establishment: High (90-100% detection rate expected)
- Data Exfiltration: Medium-High (75-90% detection rate expected)

The analyzer combines signature-based detection, behavioral analysis, and threat intelligence to identify malicious activities across these scenarios.
