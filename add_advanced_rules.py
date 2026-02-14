#!/usr/bin/env python3
"""
Script to add additional advanced detection rules to enhance the tool.
"""

import os
import json
from github import Github
import configparser

def main():
    print("Adding additional advanced detection rules...")
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

    # Define additional advanced detection rules
    additional_rules = {
        "PowerShell Obfuscation": [
            {"pattern": r"\\b\\-enc\\b|\\-encodedcommand", "description": "PowerShell encoded command - Potential obfuscation"},
            {"pattern": r"\\b\\[char\\]\\[", "description": "Character array conversion - Potential obfuscation"},
            {"pattern": r"\\bjoin\\(\\\"\\\"\\)|\\-join\\s+\\\"\\\"", "description": "String join operations - Potential obfuscation"},
            {"pattern": r"\\b\\[convert\\]::frombase64", "description": "Base64 conversion - Potential obfuscation"},
            {"pattern": r"\\b\\[text.encoding\\]::", "description": "Text encoding usage - Potential obfuscation"},
            {"pattern": r"\\bniex\\b|\\bnvoke-expression\\b", "description": "PowerShell IEX variants - Potential code execution"},
            {"pattern": r"\\b\\[byte\\[]\\]", "description": "Byte array usage - Potential obfuscation"},
            {"pattern": r"\\b\\[string\\]::", "description": "String manipulation - Potential obfuscation"},
            {"pattern": r"\\b\\[system.text.encoding\\]", "description": "System text encoding - Potential obfuscation"},
            {"pattern": r"\\b\\[system.convert\\]", "description": "System convert - Potential obfuscation"},
        ],
        "Fileless Malware Techniques": [
            {"pattern": r"\\bcomsvcs\\.dll\\b.*\\bmini\\b", "description": "COM services DLL usage for process dump - Potential credential theft"},
            {"pattern": r"\\bmsxsl\\.exe\\b", "description": "MSXSL processor - Potential fileless execution"},
            {"pattern": r"\\bregsvr32\\b.*scrobj\\.dll", "description": "RegSvr32 with scrobj.dll - Potential fileless execution"},
            {"pattern": r"\\bmshta\\.exe\\b.*\\.sct", "description": "MSHTA with SCT file - Potential fileless execution"},
            {"pattern": r"\\bpowershell\\b.*\\-w\\s+hidden", "description": "Hidden PowerShell window - Potential stealth execution"},
            {"pattern": r"\\bpowersploit\\b|\\bempire\\b|\\bcobalt\\b", "description": "Common penetration testing frameworks"},
            {"pattern": r"\\bamsi\\.disable\\b|\\bamsiutils\\b", "description": "AMSI bypass attempts"},
            {"pattern": r"\\bset\\s+mppreference\\b.*\\-disablerealtimemonitoring", "description": "Disabling Windows Defender - Potential evasion"},
            {"pattern": r"\\b\\-windowstyle\\s+hidden", "description": "Hidden window style - Potential stealth execution"},
            {"pattern": r"\\b\\-executionpolicy\\s+bypass", "description": "Execution policy bypass - Potential script execution"},
        ],
        "Registry Persistence": [
            {"pattern": r"\\breg\\b.*\\bcurrentversion\\b.*\\brun\\b", "description": "CurrentVersion Run key modification - Potential persistence"},
            {"pattern": r"\\breg\\b.*\\bcurrentversion\\b.*\\bexplorer\\b.*\\brun\\b", "description": "Explorer Run key modification - Potential persistence"},
            {"pattern": r"\\breg\\b.*\\bcurrentversion\\b.*\\bwinlogon\\b", "description": "Winlogon key modification - Potential persistence"},
            {"pattern": r"\\breg\\b.*\\bcurrentversion\\b.*\\bservice\\b", "description": "Service key modification - Potential persistence"},
            {"pattern": r"\\breg\\b.*\\bcurrentversion\\b.*\\bshell\\b", "description": "Shell key modification - Potential persistence"},
            {"pattern": r"\\breg\\b.*\\bcurrentversion\\b.*\\bpolicies\\b", "description": "Policies key modification - Potential persistence"},
            {"pattern": r"\\breg\\b.*\\bcurrentversion\\b.*\\binternet\\ssettings\\b", "description": "Internet settings modification - Potential persistence"},
            {"pattern": r"\\breg\\b.*\\bcurrentversion\\b.*\\bwindows\\b.*\\bcurrentversion\\b", "description": "Windows startup modification - Potential persistence"},
            {"pattern": r"\\breg\\b.*\\bcurrentversion\\b.*\\bshell\\sextensions\\b", "description": "Shell extensions modification - Potential persistence"},
            {"pattern": r"\\breg\\b.*\\bcurrentversion\\b.*\\bapp\\spaths\\b", "description": "Application paths modification - Potential persistence"},
        ],
        "Process Injection and Hollowing": [
            {"pattern": r"\\bmavinject\\.exe\\b", "description": "MavInject process injection - Potential code injection"},
            {"pattern": r"\\binject.*\\.dll", "description": "DLL injection tool usage - Potential code injection"},
            {"pattern": r"\\bprocdump\\b.*\\baccepteula\\b", "description": "ProcDump usage - Potential process dumping"},
            {"pattern": r"\\btaskmgr\\.exe\\b.*\\b-2", "description": "Task Manager with parameter - Potential process manipulation"},
            {"pattern": r"\\bcreateprocess\\b|\\bcreateremotethread\\b", "description": "Process creation/thread injection API calls"},
            {"pattern": r"\\bvirtualallocex\\b|\\bwriteprocessmemory\\b", "description": "Memory allocation/writing - Potential process injection"},
            {"pattern": r"\\bqueueapcthread\\b", "description": "APC queue injection - Potential process injection"},
            {"pattern": r"\\bsetthreadcontext\\b", "description": "Thread context manipulation - Potential process injection"},
            {"pattern": r"\\bnormaliz\\.dll\\b.*\\bcalcc\\b", "description": "Normaliz.dll abuse - Potential DLL sideloading"},
            {"pattern": r"\\bntdll\\.dll\\b.*\\bcalcc\\b", "description": "NTDLL abuse - Potential DLL sideloading"},
        ],
        "Credential Dumping": [
            {"pattern": r"\\bmimikatz\\b", "description": "Mimikatz usage - Credential dumping"},
            {"pattern": r"\\bsekurlsa\\:\\:logonpasswords\\b", "description": "Mimikatz logon passwords - Credential dumping"},
            {"pattern": r"\\blsadump\\:\\:sam\\b", "description": "LSADump SAM dump - Credential dumping"},
            {"pattern": r"\\blsadump\\:\\:secrets\\b", "description": "LSADump secrets - Credential dumping"},
            {"pattern": r"\\blsadump\\:\\:cache\\b", "description": "LSADump cache - Credential dumping"},
            {"pattern": r"\\bdpapi\\:\\:masterkey\\b", "description": "DPAPI masterkey - Credential dumping"},
            {"pattern": r"\\bdpapi\\:\\:cred\\b", "description": "DPAPI credentials - Credential dumping"},
            {"pattern": r"\\bdpapi\\:\\:vault\\b", "description": "DPAPI vault - Credential dumping"},
            {"pattern": r"\\bprocdump\\b.*lsass", "description": "ProcDump on LSASS - Potential credential dumping"},
            {"pattern": r"\\btasklist\\b.*lsass", "description": "Tasklist on LSASS - Reconnaissance for credential dumping"},
        ],
        "Network Beaconing and C2": [
            {"pattern": r"\\bcurl\\b.*http.*\\|\\s*cmd\\b|\\bpowershell\\b", "description": "Curl with pipe to cmd/powershell - Potential C2"},
            {"pattern": r"\\bwget\\b.*http.*\\|\\s*cmd\\b|\\bpowershell\\b", "description": "Wget with pipe to cmd/powershell - Potential C2"},
            {"pattern": r"\\bicmpping\\b.*\\-r\\b", "description": "ICMP ping with routing - Potential covert channel"},
            {"pattern": r"\\bnetsh\\b.*\\bportproxy\\b", "description": "Port proxy configuration - Potential C2"},
            {"pattern": r"\\bnetsh\\b.*\\bfirewall\\b.*\\badd\\b.*\\brule\\b", "description": "Firewall rule addition - Potential C2"},
            {"pattern": r"\\bnetstat\\b.*\\-an", "description": "Netstat with all connections - Reconnaissance"},
            {"pattern": r"\\bnbtstat\\b.*\\-a", "description": "NetBIOS statistics - Reconnaissance"},
            {"pattern": r"\\barp\\b.*\\-a", "description": "ARP table inspection - Reconnaissance"},
            {"pattern": r"\\bnltest\\b.*\\b/domain_trusts\\b", "description": "Domain trust enumeration - Reconnaissance"},
            {"pattern": r"\\bnltest\\b.*\\b/server:\\b", "description": "Server enumeration - Reconnaissance"},
        ],
        "Linux/Unix Specific Threats": [
            {"pattern": r"\\bchmod\\s+\\d{3,4}\\s*/tmp/.*\\.(sh|py|pl|c|cpp)\\b", "description": "Making temp file executable - Potential malware"},
            {"pattern": r"\\bcurl\\s+.*\\|\\s*sh\\b", "description": "Curl piped to shell - Potential remote code execution"},
            {"pattern": r"\\bwget\\s+.*\\|\\s*sh\\b", "description": "Wget piped to shell - Potential remote code execution"},
            {"pattern": r"\\bcurl\\s+.*\\-o\\s*/tmp/.*\\|\\s*chmod\\b", "description": "Download and execute pattern"},
            {"pattern": r"\\bnc\\s+.*\\-e\\b", "description": "Netcat with execute option - Potential reverse shell"},
            {"pattern": r"\\bncat\\s+.*\\-e\\b", "description": "Ncat with execute option - Potential reverse shell"},
            {"pattern": r"\\bssh\\s+.*\\-R\\b", "description": "SSH remote port forwarding - Potential tunneling"},
            {"pattern": r"\\bssh\\s+.*\\-L\\b", "description": "SSH local port forwarding - Potential tunneling"},
            {"pattern": r"\\bcrontab\\s+.*\\-r\\b", "description": "Crontab removal - Potential persistence removal"},
            {"pattern": r"\\becr\\s+\\$\\(.*\\)\\s*>\\s*/etc/passwd\\b", "description": "Writing to system files - Potential privilege escalation"},
        ],
        "macOS Specific Threats": [
            {"pattern": r"\\blaunchctl\\b.*\\bload\\b", "description": "Launchctl load - Potential persistence"},
            {"pattern": r"\\blaunchctl\\b.*\\bunload\\b", "description": "Launchctl unload - Potential persistence manipulation"},
            {"pattern": r"\\blaunchctl\\b.*\\bstart\\b", "description": "Launchctl start - Potential execution"},
            {"pattern": r"\\blaunchctl\\b.*\\bstop\\b", "description": "Launchctl stop - Potential execution"},
            {"pattern": r"\\bdefaults\\b.*\\bwrite\\b", "description": "Defaults write - Potential configuration manipulation"},
            {"pattern": r"\\bplutil\\b.*\\b\\-replace\\b", "description": "PLIST utility - Potential configuration manipulation"},
            {"pattern": r"\\bosascript\\b.*\\bdo\\s+shell\\s+script\\b", "description": "OSA script with shell execution - Potential privilege escalation"},
            {"pattern": r"\\bpwpolicy\\b.*\\bsetpassword\\b", "description": "Password policy manipulation"},
            {"pattern": r"\\bsystemsetup\\b.*\\bset\\b", "description": "System setup manipulation"},
            {"pattern": r"\\btccutil\\b.*\\breset\\b", "description": "Transparency, Consent, and Control utility reset - Privacy bypass"},
        ]
    }

    try:
        # Get the current rules.json file
        current_rules = repo.get_contents("rules.json", ref="main")
        current_rules_content = current_rules.decoded_content.decode('utf-8')
        rules_data = json.loads(current_rules_content)
        
        # Add the new advanced rules to the appropriate sections
        for category, rules in additional_rules.items():
            if "Windows" not in rules_data:
                rules_data["Windows"] = {}
            
            if category not in rules_data["Windows"]:
                rules_data["Windows"][category] = []
            
            # Add the new rules
            for rule in rules:
                # Check if the rule already exists to avoid duplicates
                exists = False
                for existing_rule in rules_data["Windows"][category]:
                    if existing_rule["pattern"] == rule["pattern"]:
                        exists = True
                        break
                
                if not exists:
                    rules_data["Windows"][category].append(rule)
        
        # Also add Linux and macOS specific rules if they don't exist
        for os_name in ["Linux", "macOS"]:
            if os_name not in rules_data:
                rules_data[os_name] = {}
            
            if f"{os_name} Specific Threats" in additional_rules:
                category = f"{os_name} Specific Threats"
                if category not in rules_data[os_name]:
                    rules_data[os_name][category] = []
                
                for rule in additional_rules[category]:
                    exists = False
                    for existing_rule in rules_data[os_name][category]:
                        if existing_rule["pattern"] == rule["pattern"]:
                            exists = True
                            break
                    
                    if not exists:
                        rules_data[os_name][category].append(rule)
        
        # Convert back to JSON string
        updated_rules_content = json.dumps(rules_data, indent=2)
        
        # Update the rules.json file
        repo.update_file(
            path="rules.json",
            message="Add advanced detection rules for PowerShell obfuscation, fileless malware, and other threats",
            content=updated_rules_content,
            sha=current_rules.sha,
            branch="main"
        )
        
        total_new_rules = sum(len(rules) for rules in additional_rules.values())
        print(f"✅ Successfully added {total_new_rules} additional advanced detection rules to the repository")
        
    except Exception as e:
        print(f"❌ Error updating rules.json: {e}")

    print("\n✅ Completed adding additional advanced detection rules.")

if __name__ == "__main__":
    main()