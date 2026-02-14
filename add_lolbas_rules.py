#!/usr/bin/env python3
"""
Script to add LOLBAS (Living Off The Land Binaries and Scripts) rules to enhance detection capabilities.
"""

import os
import json
import requests
from github import Github
import configparser

def main():
    print("Adding LOLBAS (Living Off The Land Binaries and Scripts) rules...")
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

    # Fetch LOLBAS data from their GitHub repository
    print("Fetching LOLBAS data...")
    try:
        # Get the list of LOLBAS binaries from the repository
        lolbas_repo = g.get_repo("LOLBAS-Project/LOLBAS")
        
        # Get the content of the Windows binaries directory
        contents = lolbas_repo.get_contents("yaml/Windows/Binaries")
        
        lolbas_rules = []
        for content_file in contents:
            if content_file.name.endswith('.yaml'):
                print(f"Processing {content_file.name}...")
                
                # Get the raw content of the YAML file
                yaml_content = requests.get(f"https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/yaml/Windows/Binaries/{content_file.name}").text
                
                # Convert YAML to a simple format we can use for rules
                # This is a simplified approach - in practice, we'd parse the YAML properly
                lines = yaml_content.split('\n')
                
                program_name = ""
                description = ""
                detection_strings = []
                
                for line in lines:
                    if line.startswith('Name:'):
                        program_name = line.split(':', 1)[1].strip()
                    elif line.startswith('Description:'):
                        description = line.split(':', 1)[1].strip()
                    elif 'Usecase:' in line or 'Category:' in line:
                        # Extract potential command patterns from use cases
                        if ':' in line:
                            usecase = line.split(':', 1)[1].strip()
                            if usecase:
                                detection_strings.append(usecase.lower())
                
                if program_name:
                    # Create a rule for the binary
                    rule_pattern = f"\\b{program_name.lower()}\\b"
                    
                    # Create a description based on the program name and any available info
                    rule_description = f"Suspicious usage of {program_name} - Potential LOLBIN"
                    if description:
                        rule_description += f": {description}"
                    
                    lolbas_rules.append({
                        "pattern": rule_pattern,
                        "description": rule_description
                    })
                    
                    # Add specific usage patterns if available
                    for detection_string in detection_strings:
                        if detection_string and detection_string != program_name.lower():
                            lolbas_rules.append({
                                "pattern": f"{program_name.lower()}.*{detection_string}",
                                "description": f"Suspicious {program_name} usage: {detection_string}"
                            })
        
        print(f"Retrieved {len(lolbas_rules)} LOLBAS rules")
        
    except Exception as e:
        print(f"Error fetching LOLBAS data: {e}")
        # Fallback to a predefined set of common LOLBAS rules
        print("Using predefined LOLBAS rules...")
        lolbas_rules = [
            {"pattern": r"\breg\s+sav", "description": "Registry save operation - Potential data exfiltration"},
            {"pattern": r"\breg\s+export", "description": "Registry export operation - Potential credential theft"},
            {"pattern": r"\breg\s+query", "description": "Registry query operation - Potential information gathering"},
            {"pattern": r"\bwmic\s+process\s+call", "description": "WMIC process call - Potential process manipulation"},
            {"pattern": r"\bwmic\s+shadowcopy", "description": "WMIC shadowcopy - Potential volume shadow copy manipulation"},
            {"pattern": r"\bpsexec\b", "description": "PsExec usage - Potential lateral movement"},
            {"pattern": r"\bpsexec\b", "description": "PsExec lowercase usage - Potential lateral movement"},
            {"pattern": r"\bschtasks\b", "description": "Scheduled tasks manipulation - Potential persistence"},
            {"pattern": r"\bat\b\s+", "description": "Legacy scheduled tasks - Potential persistence"},
            {"pattern": r"\bnet\s+user\b", "description": "Net user command - Potential account manipulation"},
            {"pattern": r"\bnet\s+group\b", "description": "Net group command - Potential privilege escalation"},
            {"pattern": r"\bnet\s+localgroup\b", "description": "Net localgroup command - Potential privilege escalation"},
            {"pattern": r"\bnetsh\b", "description": "Netsh command - Potential firewall/network configuration"},
            {"pattern": r"\bvssadmin\b", "description": "VSSAdmin command - Potential volume shadow copy manipulation"},
            {"pattern": r"\bcd /d \"%temp%\"", "description": "Changing to temp directory - Potential malware execution"},
            {"pattern": r"\bcmd\s+/c\b|\bcmd\s+/k\b", "description": "CMD with /c or /k flags - Potential command execution"},
            {"pattern": r"\bcertutil\b", "description": "CertUtil usage - Potential file download/encoding"},
            {"pattern": r"\bbitsadmin\b", "description": "BITSAdmin usage - Potential file download"},
            {"pattern": r"\brundll32\b", "description": "Rundll32 usage - Potential DLL execution"},
            {"pattern": r"\bmshta\b", "description": "MSHTA usage - Potential script execution"},
            {"pattern": r"\bcscript\b", "description": "CScript usage - Potential script execution"},
            {"pattern": r"\bwscript\b", "description": "WScript usage - Potential script execution"},
            {"pattern": r"\bpowershell.*-exec.*bypass", "description": "PowerShell execution policy bypass"},
            {"pattern": r"\bpowershell.*-enc", "description": "PowerShell encoded command - Potential obfuscation"},
            {"pattern": r"\bpowershell.*iex", "description": "PowerShell IEX (Invoke-Expression) - Potential code execution"},
            {"pattern": r"\bpowershell.*downloadstring", "description": "PowerShell download string - Potential file download"},
            {"pattern": r"\bpowershell.*invoke-webrequest", "description": "PowerShell web request - Potential file download"},
            {"pattern": r"\bwmic.*get.*process", "description": "WMIC process enumeration"},
            {"pattern": r"\bwmic.*create", "description": "WMIC process creation - Potential execution"},
            {"pattern": r"\bwmic.*shadowcopy", "description": "WMIC shadowcopy manipulation"},
            {"pattern": r"\bforfiles\b", "description": "Forfiles usage - Potential LOLBIN"},
            {"pattern": r"\bdiskshadow\b", "description": "DiskShadow usage - Potential volume shadow copy manipulation"},
            {"pattern": r"\bmsiexec\b", "description": "MSIExec usage - Potential execution"},
            {"pattern": r"\bcmdkey\b", "description": "CMDKey usage - Potential credential manipulation"},
            {"pattern": r"\bdsget\b", "description": "DSGet usage - Potential information gathering"},
            {"pattern": r"\bdsquery\b", "description": "DSQuery usage - Potential information gathering"},
            {"pattern": r"\bgpsvc\b", "description": "Group Policy Service - Potential manipulation"},
            {"pattern": r"\bnetsh.*advfirewall", "description": "Netsh firewall manipulation"},
            {"pattern": r"\bnetsh.*portproxy", "description": "Netsh port proxy - Potential port forwarding"},
            {"pattern": r"\bnetsh.*wlan", "description": "Netsh WLAN commands - Potential wireless enumeration"},
            {"pattern": r"\bnet1\b", "description": "Net1 command - Potential network enumeration"},
            {"pattern": r"\bntdsutil\b", "description": "NTDSUtil usage - Potential database manipulation"},
            {"pattern": r"\bqwinsta\b", "description": "Qwinsta usage - Potential session enumeration"},
            {"pattern": r"\bquery\b", "description": "Query command - Potential session/process enumeration"},
            {"pattern": r"\brasdial\b", "description": "Rasdial usage - Potential connection manipulation"},
            {"pattern": r"\btaskkill\b", "description": "Taskkill usage - Potential process termination"},
            {"pattern": r"\btasklist\b", "description": "Tasklist usage - Potential process enumeration"},
            {"pattern": r"\bwhoami\b", "description": "Whoami usage - Potential identity discovery"},
            {"pattern": r"\bicacls\b", "description": "ICACLS usage - Potential permission manipulation"},
            {"pattern": r"\btakeown\b", "description": "Takeown usage - Potential file ownership manipulation"},
            {"pattern": r"\bwevtutil\b", "description": "WEVTUtil usage - Potential event log manipulation"},
            {"pattern": r"\bwinrm\b", "description": "WinRM usage - Potential remote management"},
            {"pattern": r"\bwuauclt\b", "description": "WUAUClt usage - Potential update manipulation"},
            {"pattern": r"\bverifier\b", "description": "Verifier usage - Potential system manipulation"},
            {"pattern": r"\bappcmd\b", "description": "AppCmd usage - Potential IIS manipulation"},
            {"pattern": r"\bconfigsecuritypolicy\b", "description": "ConfigSecurityPolicy usage - Potential security policy manipulation"},
            {"pattern": r"\bcsi\b", "description": "CSI usage - Potential code compilation"},
            {"pattern": r"\bdesktopimgdownldr\b", "description": "DesktopImgDownldr usage - Potential file download"},
            {"pattern": r"\bdiantz\b", "description": "DiAntz usage - Potential compression/obfuscation"},
            {"pattern": r"\beventvwr\b", "description": "EventVWR usage - Potential UAC bypass"},
            {"pattern": r"\bfinger\b", "description": "Finger usage - Potential network reconnaissance"},
            {"pattern": r"\bfltmc\b", "description": "FltMc usage - Potential filter manipulation"},
            {"pattern": r"\bgfxcorr\b", "description": "GfxCorr usage - Potential graphics driver manipulation"},
            {"pattern": r"\bhashgen\b", "description": "HashGen usage - Potential hash computation"},
            {"pattern": r"\bhivedump\b", "description": "HiveDump usage - Potential registry manipulation"},
            {"pattern": r"\bmakecab\b", "description": "MakeCab usage - Potential compression"},
            {"pattern": r"\bmanage-bde\b", "description": "Manage-BDE usage - Potential BitLocker manipulation"},
            {"pattern": r"\bmobs\b", "description": "MOBS usage - Potential object manipulation"},
            {"pattern": r"\bmoveuser\b", "description": "MoveUser usage - Potential user profile manipulation"},
            {"pattern": r"\bnetdom\b", "description": "NetDom usage - Potential domain manipulation"},
            {"pattern": r"\bnltest\b", "description": "NLTest usage - Potential domain enumeration"},
            {"pattern": r"\bopenssh\b", "description": "OpenSSH usage - Potential secure shell"},
            {"pattern": r"\bpackager\b", "description": "Packager usage - Potential COM object manipulation"},
            {"pattern": r"\bpktmon\b", "description": "PktMon usage - Potential packet monitoring"},
            {"pattern": r"\bpresentationhost\b", "description": "PresentationHost usage - Potential XAML execution"},
            {"pattern": r"\bprintbrm\b", "description": "PrintBrm usage - Potential printer backup/restore"},
            {"pattern": r"\bprovtool\b", "description": "ProvTool usage - Potential provisioning"},
            {"pattern": r"\bpsexecsvc\b", "description": "PsExecSvc usage - Potential service"},
            {"pattern": r"\brasautou\b", "description": "RasAutoU usage - Potential connection automation"},
            {"pattern": r"\brasdialer\b", "description": "RasDialer usage - Potential connection manipulation"},
            {"pattern": r"\brpcping\b", "description": "RpcPing usage - Potential RPC testing"},
            {"pattern": r"\bscriptrunner\b", "description": "ScriptRunner usage - Potential script execution"},
            {"pattern": r"\bsetres\b", "description": "SetRes usage - Potential resolution manipulation"},
            {"pattern": r"\bshrpubw\b", "description": "ShrPubW usage - Potential share publishing"},
            {"pattern": r"\bslui\b", "description": "SLUI usage - Potential licensing manipulation"},
            {"pattern": r"\bstordiag\b", "description": "StorDiag usage - Potential storage diagnostics"},
            {"pattern": r"\bsyncappvpublishingserver\b", "description": "SyncAppvPublishingServer usage - Potential App-V manipulation"},
            {"pattern": r"\bsysreset\b", "description": "SysReset usage - Potential system reset"},
            {"pattern": r"\bttdstarter\b", "description": "TTDStarter usage - Potential trace replay"},
            {"pattern": r"\btypeperf\b", "description": "TypePerf usage - Potential performance monitoring"},
            {"pattern": r"\butilman\b", "description": "Utilman usage - Potential accessibility feature manipulation"},
            {"pattern": r"\bvsdiagtracke\b", "description": "VsDiagTracke usage - Potential diagnostic tracking"},
            {"pattern": r"\bvsgraphicsdiag\b", "description": "VsGraphicsDiag usage - Potential graphics diagnostics"},
            {"pattern": r"\bwabuninst\b", "description": "WABUnInst usage - Potential address book manipulation"},
            {"pattern": r"\bwermgr\b", "description": "WerMgr usage - Potential error reporting manipulation"},
            {"pattern": r"\bwextract\b", "description": "WExtract usage - Potential file extraction"},
            {"pattern": r"\bwfs\b", "description": "WFS usage - Potential file system manipulation"},
            {"pattern": r"\bwiaacmgr\b", "description": "WiaAcMgr usage - Potential image acquisition manipulation"},
            {"pattern": r"\bwmic.exe\b", "description": "WMIC executable usage - Potential WMI manipulation"},
            {"pattern": r"\bwscript.exe\b", "description": "WScript executable usage - Potential script execution"},
            {"pattern": r"\bcscript.exe\b", "description": "CScript executable usage - Potential script execution"},
            {"pattern": r"\brundll32.exe\b", "description": "Rundll32 executable usage - Potential DLL execution"},
            {"pattern": r"\bmshta.exe\b", "description": "MSHTA executable usage - Potential HTML application execution"},
            {"pattern": r"\bpowershell.exe\b", "description": "PowerShell executable usage - Potential script execution"},
            {"pattern": r"\bpwsh.exe\b", "description": "PowerShell Core executable usage - Potential script execution"},
            {"pattern": r"\bcmd.exe\b", "description": "CMD executable usage - Potential command execution"},
            {"pattern": r"\breg.exe\b", "description": "Registry executable usage - Potential registry manipulation"},
            {"pattern": r"\bschtasks.exe\b", "description": "Scheduled tasks executable usage - Potential task manipulation"},
            {"pattern": r"\bnet.exe\b", "description": "Net executable usage - Potential network manipulation"},
            {"pattern": r"\bnet1.exe\b", "description": "Net1 executable usage - Potential network manipulation"},
            {"pattern": r"\bvssadmin.exe\b", "description": "VSSAdmin executable usage - Potential volume shadow copy manipulation"},
            {"pattern": r"\bwevtutil.exe\b", "description": "WEVTUtil executable usage - Potential event log manipulation"},
            {"pattern": r"\bcertutil.exe\b", "description": "CertUtil executable usage - Potential certificate/file manipulation"},
            {"pattern": r"\bitsadmin.exe\b", "description": "BITSAdmin executable usage - Potential file transfer"},
            {"pattern": r"\bmsiexec.exe\b", "description": "MSIExec executable usage - Potential installer manipulation"},
            {"pattern": r"\btar.exe\b", "description": "Tar executable usage - Potential archive manipulation"},
            {"pattern": r"\bcertoc.exe\b", "description": "CertOC executable usage - Potential certificate manipulation"},
            {"pattern": r"\bdriverquery.exe\b", "description": "DriverQuery executable usage - Potential driver enumeration"},
            {"pattern": r"\bexpand.exe\b", "description": "Expand executable usage - Potential file expansion"},
            {"pattern": r"\bextrac32.exe\b", "description": "Extrac32 executable usage - Potential file extraction"},
            {"pattern": r"\bfindstr.exe\b", "description": "FindStr executable usage - Potential string search"},
            {"pattern": r"\bfxssvc.exe\b", "description": "FXS SVC executable usage - Potential fax service manipulation"},
            {"pattern": r"\bgpsvc.exe\b", "description": "GPSVC executable usage - Potential group policy manipulation"},
            {"pattern": r"\bhh.exe\b", "description": "HH executable usage - Potential help file execution"},
            {"pattern": r"\biexpress.exe\b", "description": "IExpress executable usage - Potential SFX creation"},
            {"pattern": r"\bklist.exe\b", "description": "KList executable usage - Potential Kerberos ticket manipulation"},
            {"pattern": r"\bksetup.exe\b", "description": "KSetup executable usage - Potential Kerberos setup"},
            {"pattern": r"\blegalnotice.exe\b", "description": "LegalNotice executable usage - Potential message box manipulation"},
            {"pattern": r"\blpremove.exe\b", "description": "LPRemove executable usage - Potential license pack removal"},
            {"pattern": r"\bmagnify.exe\b", "description": "Magnify executable usage - Potential accessibility feature manipulation"},
            {"pattern": r"\bmftrace.exe\b", "description": "MFTrace executable usage - Potential media foundation tracing"},
            {"pattern": r"\bmigui.exe\b", "description": "MigUI executable usage - Potential migration UI"},
            {"pattern": r"\bnarrator.exe\b", "description": "Narrator executable usage - Potential accessibility feature manipulation"},
            {"pattern": r"\bnetsh.exe\b", "description": "Netsh executable usage - Potential network configuration"},
            {"pattern": r"\bnslookup.exe\b", "description": "NSLookup executable usage - Potential DNS queries"},
            {"pattern": r"\bntdsutil.exe\b", "description": "NTDSUtil executable usage - Potential Active Directory manipulation"},
            {"pattern": r"\bodbcad32.exe\b", "description": "ODBCCP32 executable usage - Potential ODBC configuration"},
            {"pattern": r"\bodbccp32.exe\b", "description": "ODBCCP32 executable usage - Potential ODBC configuration"},
            {"pattern": r"\boobeload.exe\b", "description": "OOBELOAD executable usage - Potential OOBE manipulation"},
            {"pattern": r"\bpktmon.exe\b", "description": "PktMon executable usage - Potential packet monitoring"},
            {"pattern": r"\bpresentationhost.exe\b", "description": "PresentationHost executable usage - Potential XAML execution"},
            {"pattern": r"\bpsr.exe\b", "description": "PSR executable usage - Potential problem steps recorder"},
            {"pattern": r"\bquickassist.exe\b", "description": "QuickAssist executable usage - Potential remote assistance"},
            {"pattern": r"\brasautou.exe\b", "description": "RasAutoU executable usage - Potential connection automation"},
            {"pattern": r"\brasdialer.exe\b", "description": "RasDialer executable usage - Potential connection manipulation"},
            {"pattern": r"\brstrui.exe\b", "description": "RSTRUI executable usage - Potential system restore"},
            {"pattern": r"\bsettcp.exe\b", "description": "SetTCP executable usage - Potential TCP configuration"},
            {"pattern": r"\bshrpubw.exe\b", "description": "ShrPubW executable usage - Potential share publishing"},
            {"pattern": r"\bspellcheckinghost.exe\b", "description": "SpellCheckingHost executable usage - Potential spell check manipulation"},
            {"pattern": r"\bstordiag.exe\b", "description": "StorDiag executable usage - Potential storage diagnostics"},
            {"pattern": r"\bsynophoto.exe\b", "description": "SynoPhoto executable usage - Potential Synology photo manipulation"},
            {"pattern": r"\bsyskey.exe\b", "description": "SysKey executable usage - Potential SAM database protection"},
            {"pattern": r"\btar.exe\b", "description": "Tar executable usage - Potential archive manipulation"},
            {"pattern": r"\bttdstarter.exe\b", "description": "TTDStarter executable usage - Potential trace replay"},
            {"pattern": r"\btypeperf.exe\b", "description": "TypePerf executable usage - Potential performance monitoring"},
            {"pattern": r"\buacdiaglauncher.exe\b", "description": "UACDiagLauncher executable usage - Potential UAC diagnostics"},
            {"pattern": r"\butilman.exe\b", "description": "Utilman executable usage - Potential accessibility feature manipulation"},
            {"pattern": r"\bwabuninst.exe\b", "description": "WABUnInst executable usage - Potential address book manipulation"},
            {"pattern": r"\bwermgr.exe\b", "description": "WerMgr executable usage - Potential error reporting manipulation"},
            {"pattern": r"\bwfs.exe\b", "description": "WFS executable usage - Potential file system manipulation"},
            {"pattern": r"\bwiaacmgr.exe\b", "description": "WiaAcMgr executable usage - Potential image acquisition manipulation"},
            {"pattern": r"\bwscript.exe\b", "description": "WScript executable usage - Potential script execution"},
            {"pattern": r"\bxwizard.exe\b", "description": "XWizard executable usage - Potential wizard execution"},
        ]

    try:
        # Get the current rules.json file
        current_rules = repo.get_contents("rules.json", ref="main")
        current_rules_content = current_rules.decoded_content.decode('utf-8')
        rules_data = json.loads(current_rules_content)
        
        # Add the new LOLBAS rules to the Windows section
        if "Windows" not in rules_data:
            rules_data["Windows"] = {}
        
        if "LOLBAS - Living Off The Land Binaries" not in rules_data["Windows"]:
            rules_data["Windows"]["LOLBAS - Living Off The Land Binaries"] = []
        
        # Add the new rules
        for rule in lolbas_rules:
            # Check if the rule already exists to avoid duplicates
            exists = False
            for existing_rule in rules_data["Windows"]["LOLBAS - Living Off The Land Binaries"]:
                if existing_rule["pattern"] == rule["pattern"]:
                    exists = True
                    break
            
            if not exists:
                rules_data["Windows"]["LOLBAS - Living Off The Land Binaries"].append(rule)
        
        # Convert back to JSON string
        updated_rules_content = json.dumps(rules_data, indent=2)
        
        # Update the rules.json file
        repo.update_file(
            path="rules.json",
            message="Add LOLBAS (Living Off The Land Binaries and Scripts) rules for enhanced detection",
            content=updated_rules_content,
            sha=current_rules.sha,
            branch="main"
        )
        
        print(f"✅ Successfully added {len(lolbas_rules)} LOLBAS rules to the repository")
        
    except Exception as e:
        print(f"❌ Error updating rules.json: {e}")

    print("\n✅ Completed adding LOLBAS rules to enhance detection capabilities.")

if __name__ == "__main__":
    main()