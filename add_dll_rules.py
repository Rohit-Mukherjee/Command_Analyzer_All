#!/usr/bin/env python3
"""
Script to add DLL loading detection rules to enhance the tool.
"""

import os
import json
from github import Github
import configparser

def main():
    print("Adding DLL loading detection rules...")
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

    # Define DLL loading detection rules
    dll_loading_rules = [
        # rundll32.exe patterns
        {"pattern": r"\\brundll32\\.exe\\b.*\\bjavascript:\\b", "description": "Rundll32 with JavaScript - Potential code execution"},
        {"pattern": r"\\brundll32\\.exe\\b.*\\bzipfldr\\,", "description": "Rundll32 ZipFldr - Potential fileless execution"},
        {"pattern": r"\\brundll32\\.exe\\b.*\\bshell32\\,", "description": "Rundll32 Shell32 - Potential fileless execution"},
        {"pattern": r"\\brundll32\\.exe\\b.*\\.dll\\,\\w+", "description": "Rundll32 executing DLL function - Potential DLL sideloading"},
        {"pattern": r"\\brundll32\\b.*\\,\\s*\\d+", "description": "Rundll32 with ordinal - Potential DLL execution"},
        {"pattern": r"\\brundll32\\b.*\\b\\,\\s*Control_RunDLL\\b", "description": "Rundll32 Control_RunDLL - Potential DLL execution"},
        {"pattern": r"\\brundll32\\b.*\\b\\,\\s*DllRegisterServer\\b", "description": "Rundll32 DllRegisterServer - Potential DLL registration"},
        {"pattern": r"\\brundll32\\b.*\\b\\,\\s*DllInstall\\b", "description": "Rundll32 DllInstall - Potential DLL installation"},
        {"pattern": r"\\brundll32\\b.*\\b\\,\\s*DllUnregisterServer\\b", "description": "Rundll32 DllUnregisterServer - Potential DLL unregistration"},
        {"pattern": r"\\brundll32\\b.*\\b\\,\\s*Init\\b", "description": "Rundll32 Init function - Potential DLL initialization"},
        
        # regsvr32.exe patterns
        {"pattern": r"\\bregsvr32\\b.*\\b/s\\b.*\\b/c\\b", "description": "RegSvr32 silent and console - Potential DLL execution"},
        {"pattern": r"\\bregsvr32\\b.*\\b/n\\b.*\\b/i\\b", "description": "RegSvr32 no base and install - Potential DLL execution"},
        {"pattern": r"\\bregsvr32\\b.*\\.sct\\b", "description": "RegSvr32 with SCT file - Potential script execution"},
        {"pattern": r"\\bregsvr32\\b.*\\.dll\\b", "description": "RegSvr32 registering DLL - Potential DLL execution"},
        {"pattern": r"\\bregsvr32\\b.*\\bhttp", "description": "RegSvr32 with HTTP - Potential remote DLL download"},
        {"pattern": r"\\bregsvr32\\b.*\\bftp", "description": "RegSvr32 with FTP - Potential remote DLL download"},
        {"pattern": r"\\bregsvr32\\b.*\\b\\-n\\b", "description": "RegSvr32 with -n flag - Potential DLL sideloading"},
        {"pattern": r"\\bregsvr32\\b.*\\b\\-s\\b", "description": "RegSvr32 with -s flag - Potential silent DLL execution"},
        {"pattern": r"\\bregsvr32\\b.*\\b\\%temp%\\b", "description": "RegSvr32 with temp path - Potential malicious DLL execution"},
        {"pattern": r"\\bregsvr32\\b.*\\b\\%appdata%\\b", "description": "RegSvr32 with appdata path - Potential malicious DLL execution"},
        
        # msiexec.exe patterns
        {"pattern": r"\\bmsiexec\\b.*\\b/a\\b", "description": "Msiexec administrative install - Potential DLL execution"},
        {"pattern": r"\\bmsiexec\\b.*\\b/q\\b", "description": "Msiexec quiet install - Potential hidden DLL execution"},
        {"pattern": r"\\bmsiexec\\b.*\\b/passive\\b", "description": "Msiexec passive install - Potential hidden DLL execution"},
        {"pattern": r"\\bmsiexec\\b.*\\.msi\\b", "description": "Msiexec MSI execution - Potential DLL execution"},
        {"pattern": r"\\bmsiexec\\b.*\\bhttp", "description": "Msiexec with HTTP - Potential remote MSI download"},
        {"pattern": r"\\bmsiexec\\b.*\\bftp", "description": "Msiexec with FTP - Potential remote MSI download"},
        {"pattern": r"\\bmsiexec\\b.*\\b\\%temp%\\b", "description": "Msiexec with temp path - Potential malicious MSI execution"},
        {"pattern": r"\\bmsiexec\\b.*\\b\\%appdata%\\b", "description": "Msiexec with appdata path - Potential malicious MSI execution"},
        {"pattern": r"\\bmsiexec\\b.*\\b\\-i\\b", "description": "Msiexec install flag - Potential DLL execution"},
        {"pattern": r"\\bmsiexec\\b.*\\b\\-x\\b", "description": "Msiexec uninstall flag - Potential DLL execution"},
        
        # odbcconf.exe patterns
        {"pattern": r"\\bodbcconf\\b.*\\b/c\\b.*\\bregsvr\\b", "description": "Odbcconf with regsvr - Potential DLL registration"},
        {"pattern": r"\\bodbcconf\\b.*\\b/s\\b", "description": "Odbcconf silent - Potential DLL execution"},
        {"pattern": r"\\bodbcconf\\b.*\\.dll\\b", "description": "Odbcconf with DLL - Potential DLL registration"},
        {"pattern": r"\\bodbcconf\\b.*\\bregsvr\\b", "description": "Odbcconf regsvr command - Potential DLL registration"},
        {"pattern": r"\\bodbcconf\\b.*\\b\\-f\\b", "description": "Odbcconf with file - Potential DLL execution"},
        {"pattern": r"\\bodbcconf\\b.*\\b\\-a\\b", "description": "Odbcconf with attribute - Potential DLL execution"},
        {"pattern": r"\\bodbcconf\\b.*\\b\\-c\\b", "description": "Odbcconf with command - Potential DLL execution"},
        {"pattern": r"\\bodbcconf\\b.*\\b\\-r\\b", "description": "Odbcconf with register - Potential DLL execution"},
        {"pattern": r"\\bodbcconf\\b.*\\b\\%temp%\\b", "description": "Odbcconf with temp path - Potential malicious DLL execution"},
        {"pattern": r"\\bodbcconf\\b.*\\b\\%appdata%\\b", "description": "Odbcconf with appdata path - Potential malicious DLL execution"},
        
        # mshta.exe patterns
        {"pattern": r"\\bmshta\\b.*\\.sct\\b", "description": "MSHTA with SCT file - Potential script execution"},
        {"pattern": r"\\bmshta\\b.*\\.hta\\b", "description": "MSHTA with HTA file - Potential script execution"},
        {"pattern": r"\\bmshta\\b.*\\bjavascript:\\b", "description": "MSHTA with JavaScript - Potential code execution"},
        {"pattern": r"\\bmshta\\b.*\\bhttp", "description": "MSHTA with HTTP - Potential remote script download"},
        {"pattern": r"\\bmshta\\b.*\\bftp", "description": "MSHTA with FTP - Potential remote script download"},
        {"pattern": r"\\bmshta\\b.*\\b\\%temp%\\b", "description": "MSHTA with temp path - Potential malicious script execution"},
        {"pattern": r"\\bmshta\\b.*\\b\\%appdata%\\b", "description": "MSHTA with appdata path - Potential malicious script execution"},
        {"pattern": r"\\bmshta\\b.*\\b\\-embedding\\b", "description": "MSHTA embedding - Potential hidden execution"},
        {"pattern": r"\\bmshta\\b.*\\b\\-nonewwindow\\b", "description": "MSHTA nonewwindow - Potential hidden execution"},
        {"pattern": r"\\bmshta\\b.*\\b\\-silent\\b", "description": "MSHTA silent - Potential hidden execution"},
        
        # misc patterns
        {"pattern": r"\\bcertoc\\b.*\\b\\-LoadDll\\b", "description": "CertOC LoadDll - Potential DLL sideloading"},
        {"pattern": r"\\bextexport\\b.*\\b\\-LoadDll\\b", "description": "ExtExport LoadDll - Potential DLL sideloading"},
        {"pattern": r"\\bforfiles\\b.*\\b\\%temp%\\b.*\\b\\.dll\\b", "description": "Forfiles with DLL in temp - Potential DLL execution"},
        {"pattern": r"\\bforfiles\\b.*\\b\\%appdata%\\b.*\\b\\.dll\\b", "description": "Forfiles with DLL in appdata - Potential DLL execution"},
        {"pattern": r"\\bmsconfig\\b.*\\b\\-LoadDll\\b", "description": "Msconfig LoadDll - Potential DLL sideloading"},
        {"pattern": r"\\bmsdt\\b.*\\b\\-LoadDll\\b", "description": "Msdt LoadDll - Potential DLL sideloading"},
        {"pattern": r"\\bpnputil\\b.*\\b\\-i\\b", "description": "PnPUtil install driver - Potential malicious driver loading"},
        {"pattern": r"\\bregasm\\b.*\\.dll\\b", "description": "RegAsm with DLL - Potential .NET assembly registration"},
        {"pattern": r"\\bregini\\b.*\\.dll\\b", "description": "RegIni with DLL - Potential registry initialization"},
        {"pattern": r"\\bschtasks\\b.*\\b\\%temp%\\b.*\\b\\.dll\\b", "description": "Schtasks with DLL in temp - Potential scheduled DLL execution"},
        {"pattern": r"\\bschtasks\\b.*\\b\\%appdata%\\b.*\\b\\.dll\\b", "description": "Schtasks with DLL in appdata - Potential scheduled DLL execution"},
        {"pattern": r"\\bwinrm\\b.*\\binvoke\\b.*\\b\\-LoadDll\\b", "description": "WinRM invoke with LoadDll - Potential remote DLL execution"},
        {"pattern": r"\\bwmic\\b.*\\bprocess\\b.*\\bcall\\b.*\\bcreate\\b.*\\b\\.dll\\b", "description": "WMIC process call with DLL - Potential process creation with DLL"},
        {"pattern": r"\\bpowershell\\b.*\\b\\[reflection\\.assembly\\]::loadfile\\b", "description": "PowerShell Assembly.LoadFile - Potential .NET assembly loading"},
        {"pattern": r"\\bpowershell\\b.*\\badd-type\\b.*\\b-language\\b.*\\bcsharp\\b", "description": "PowerShell Add-Type C# - Potential code compilation and execution"},
        {"pattern": r"\\bpowershell\\b.*\\bimport-module\\b.*\\b\\.dll\\b", "description": "PowerShell Import-Module DLL - Potential module loading"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bloadwithpartialname\\b", "description": "PowerShell Reflection Assembly Load - Potential assembly loading"},
        {"pattern": r"\\bpowershell\\b.*\\bloadfile\\b.*\\b\\.dll\\b", "description": "PowerShell LoadFile with DLL - Potential assembly loading"},
        {"pattern": r"\\bpowershell\\b.*\\bloadfrom\\b.*\\b\\.dll\\b", "description": "PowerShell LoadFrom with DLL - Potential assembly loading"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bload\\b", "description": "PowerShell Reflection Assembly Load - Potential assembly loading"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bunsafe\\b", "description": "PowerShell Reflection Unsafe - Potential unsafe assembly loading"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.emit\\b", "description": "PowerShell Reflection.Emit - Potential dynamic code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b", "description": "PowerShell Reflection Define - Potential dynamic assembly creation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bdynamic\\b", "description": "PowerShell Dynamic Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bruntime\\b", "description": "PowerShell Runtime Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\banonymous\\b", "description": "PowerShell Anonymous Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bmodule\\b", "description": "PowerShell Module Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\btype\\b", "description": "PowerShell Type Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bmethod\\b", "description": "PowerShell Method Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bfield\\b", "description": "PowerShell Field Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bproperty\\b", "description": "PowerShell Property Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bevent\\b", "description": "PowerShell Event Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bconstructor\\b", "description": "PowerShell Constructor Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bdestructor\\b", "description": "PowerShell Destructor Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\binterface\\b", "description": "PowerShell Interface Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\benum\\b", "description": "PowerShell Enum Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bstruct\\b", "description": "PowerShell Struct Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bclass\\b", "description": "PowerShell Class Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bnamespace\\b", "description": "PowerShell Namespace Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bassembly\\b", "description": "PowerShell Assembly Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bmodulebuilder\\b", "description": "PowerShell ModuleBuilder Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\btypebuilder\\b", "description": "PowerShell TypeBuilder Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bmethodbuilder\\b", "description": "PowerShell MethodBuilder Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bfieldbuilder\\b", "description": "PowerShell FieldBuilder Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bpropertybuilder\\b", "description": "PowerShell PropertyBuilder Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\beventbuilder\\b", "description": "PowerShell EventBuilder Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bconstructorbuilder\\b", "description": "PowerShell ConstructorBuilder Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bparameterbuilder\\b", "description": "PowerShell ParameterBuilder Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bgeneric\\b", "description": "PowerShell Generic Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bgeneric\\b.*\\btype\\b", "description": "PowerShell Generic Type Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bgeneric\\b.*\\bmethod\\b", "description": "PowerShell Generic Method Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bgeneric\\b.*\\bparameter\\b", "description": "PowerShell Generic Parameter Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bgeneric\\b.*\\bargument\\b", "description": "PowerShell Generic Argument Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bgeneric\\b.*\\binstance\\b", "description": "PowerShell Generic Instance Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bgeneric\\b.*\\binvoke\\b", "description": "PowerShell Generic Invoke Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bgeneric\\b.*\\bcall\\b", "description": "PowerShell Generic Call Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bgeneric\\b.*\\bnew\\b", "description": "PowerShell Generic New Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bgeneric\\b.*\\bcreate\\b", "description": "PowerShell Generic Create Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bgeneric\\b.*\\binstance\\b.*\\bcreate\\b", "description": "PowerShell Generic Instance Create Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bgeneric\\b.*\\binstance\\b.*\\bnew\\b", "description": "PowerShell Generic Instance New Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bgeneric\\b.*\\binstance\\b.*\\binvoke\\b", "description": "PowerShell Generic Instance Invoke Assembly - Potential runtime code generation"},
        {"pattern": r"\\bpowershell\\b.*\\breflection\\.assembly\\b.*\\bdefine\\b.*\\bgeneric\\b.*\\binstance\\b.*\\bcall\\b", "description": "PowerShell Generic Instance Call Assembly - Potential runtime code generation"},
    ]

    try:
        # Get the current rules.json file
        current_rules = repo.get_contents("rules.json", ref="main")
        current_rules_content = current_rules.decoded_content.decode('utf-8')
        rules_data = json.loads(current_rules_content)
        
        # Add the new DLL loading rules to the Windows section
        if "Windows" not in rules_data:
            rules_data["Windows"] = {}
        
        if "DLL Loading Techniques" not in rules_data["Windows"]:
            rules_data["Windows"]["DLL Loading Techniques"] = []
        
        # Add the new rules
        for rule in dll_loading_rules:
            # Check if the rule already exists to avoid duplicates
            exists = False
            for existing_rule in rules_data["Windows"]["DLL Loading Techniques"]:
                if existing_rule["pattern"] == rule["pattern"]:
                    exists = True
                    break
            
            if not exists:
                rules_data["Windows"]["DLL Loading Techniques"].append(rule)
        
        # Convert back to JSON string
        updated_rules_content = json.dumps(rules_data, indent=2)
        
        # Update the rules.json file
        repo.update_file(
            path="rules.json",
            message="Add DLL loading detection rules for enhanced security monitoring",
            content=updated_rules_content,
            sha=current_rules.sha,
            branch="main"
        )
        
        print(f"✅ Successfully added {len(dll_loading_rules)} DLL loading detection rules to the repository")
        
    except Exception as e:
        print(f"❌ Error updating rules.json: {e}")

    print("\n✅ Completed adding DLL loading detection rules.")

if __name__ == "__main__":
    main()