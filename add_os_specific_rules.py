#!/usr/bin/env python3
"""
Script to add missing macOS and Linux persistence and firewall rules.
"""

import os
import json
from github import Github
import configparser

def main():
    print("Adding missing macOS and Linux persistence and firewall rules...")
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

    # Define additional macOS and Linux rules
    additional_os_rules = {
        "Linux": {
            "Persistence Mechanisms": [
                {"pattern": r"\\bcron\\b.*\\-e\\b|\\bcron\\b.*\\-l\\b", "description": "Cron editor/list - Potential persistence mechanism"},
                {"pattern": r"\\bcrontab\\b.*\\-e\\b|\\bcrontab\\b.*\\-l\\b", "description": "Crontab editor/list - Potential persistence mechanism"},
                {"pattern": r"\\b/etc/cron\\b", "description": "Cron directories - Potential persistence mechanism"},
                {"pattern": r"\\b/etc/anacron\\b", "description": "Anacron configuration - Potential persistence mechanism"},
                {"pattern": r"\\b/etc/at\\b", "description": "At configuration - Potential persistence mechanism"},
                {"pattern": r"\\b/etc/rc\\b", "description": "RC configuration - Potential persistence mechanism"},
                {"pattern": r"\\b/etc/init\\b", "description": "Init configuration - Potential persistence mechanism"},
                {"pattern": r"\\b/etc/systemd\\b", "description": "Systemd configuration - Potential persistence mechanism"},
                {"pattern": r"\\bsystemctl\\b.*\\benable\\b", "description": "Systemctl enable service - Potential persistence mechanism"},
                {"pattern": r"\\bsystemctl\\b.*\\bstart\\b", "description": "Systemctl start service - Potential persistence mechanism"},
                {"pattern": r"\\bupdate-rc\\.d\\b", "description": "Update RC configuration - Potential persistence mechanism"},
                {"pattern": r"\\bchkconfig\\b", "description": "Chkconfig - Potential persistence mechanism"},
                {"pattern": r"\\b~/.bashrc\\b", "description": "Bash RC configuration - Potential persistence mechanism"},
                {"pattern": r"\\b~/.profile\\b", "description": "User profile - Potential persistence mechanism"},
                {"pattern": r"\\b/etc/passwd\\b", "description": "Passwd file access - Potential persistence mechanism"},
                {"pattern": r"\\b/etc/shadow\\b", "description": "Shadow file access - Potential persistence mechanism"},
                {"pattern": r"\\b/etc/sudoers\\b", "description": "Sudoers file access - Potential persistence mechanism"},
                {"pattern": r"\\b~/.ssh/authorized_keys\\b", "description": "SSH authorized keys - Potential persistence mechanism"},
                {"pattern": r"\\b/etc/hosts\\b", "description": "Hosts file access - Potential persistence mechanism"},
                {"pattern": r"\\b/etc/fstab\\b", "description": "File system table - Potential persistence mechanism"},
            ],
            "Firewall Configuration": [
                {"pattern": r"\\biptables\\b", "description": "IPTables firewall configuration - Potential firewall manipulation"},
                {"pattern": r"\\biptables-save\\b", "description": "IPTables save - Potential firewall manipulation"},
                {"pattern": r"\\biptables-restore\\b", "description": "IPTables restore - Potential firewall manipulation"},
                {"pattern": r"\\bnftables\\b", "description": "NFTables firewall configuration - Potential firewall manipulation"},
                {"pattern": r"\\bnft\\b", "description": "NFTables command - Potential firewall manipulation"},
                {"pattern": r"\\bfirewalld\\b", "description": "Firewalld service - Potential firewall manipulation"},
                {"pattern": r"\\bfirewall-cmd\\b", "description": "Firewall command - Potential firewall manipulation"},
                {"pattern": r"\\b/etc/iptables/\\b", "description": "IPTables configuration directory - Potential firewall manipulation"},
                {"pattern": r"\\b/etc/nftables/\\b", "description": "NFTables configuration directory - Potential firewall manipulation"},
                {"pattern": r"\\b/etc/firewalld/\\b", "description": "Firewalld configuration directory - Potential firewall manipulation"},
                {"pattern": r"\\bufw\\b", "description": "UFW firewall command - Potential firewall manipulation"},
                {"pattern": r"\\bufw\\b.*\\benable\\b", "description": "UFW enable - Potential firewall manipulation"},
                {"pattern": r"\\bufw\\b.*\\bdisable\\b", "description": "UFW disable - Potential firewall manipulation"},
                {"pattern": r"\\bufw\\b.*\\ballow\\b", "description": "UFW allow - Potential firewall manipulation"},
                {"pattern": r"\\bufw\\b.*\\bdeny\\b", "description": "UFW deny - Potential firewall manipulation"},
            ]
        },
        "macOS": {
            "Persistence Mechanisms": [
                {"pattern": r"\\b~/Library/LaunchAgents/\\b", "description": "User Launch Agent - Potential persistence mechanism"},
                {"pattern": r"\\b/Library/LaunchAgents/\\b", "description": "System Launch Agent - Potential persistence mechanism"},
                {"pattern": r"\\b~/Library/LaunchDaemons/\\b", "description": "User Launch Daemon - Potential persistence mechanism"},
                {"pattern": r"\\b/Library/LaunchDaemons/\\b", "description": "System Launch Daemon - Potential persistence mechanism"},
                {"pattern": r"\\b/System/Library/LaunchAgents/\\b", "description": "System Library Launch Agent - Potential persistence mechanism"},
                {"pattern": r"\\b/System/Library/LaunchDaemons/\\b", "description": "System Library Launch Daemon - Potential persistence mechanism"},
                {"pattern": r"\\blaunchctl\\b.*\\bload\\b", "description": "LaunchCtl load - Potential persistence mechanism"},
                {"pattern": r"\\blaunchctl\\b.*\\bunload\\b", "description": "LaunchCtl unload - Potential persistence mechanism"},
                {"pattern": r"\\blaunchctl\\b.*\\bstart\\b", "description": "LaunchCtl start - Potential persistence mechanism"},
                {"pattern": r"\\blaunchctl\\b.*\\bstop\\b", "description": "LaunchCtl stop - Potential persistence mechanism"},
                {"pattern": r"\\blaunchctl\\b.*\\benable\\b", "description": "LaunchCtl enable - Potential persistence mechanism"},
                {"pattern": r"\\blaunchctl\\b.*\\bdisable\\b", "description": "LaunchCtl disable - Potential persistence mechanism"},
                {"pattern": r"\\b~/Library/Preferences/\\b", "description": "User preferences - Potential persistence mechanism"},
                {"pattern": r"\\b/Library/Preferences/\\b", "description": "System preferences - Potential persistence mechanism"},
                {"pattern": r"\\b/System/Library/Preferences/\\b", "description": "System Library preferences - Potential persistence mechanism"},
                {"pattern": r"\\b~/Library/LaunchAgents/.*\\.plist\\b", "description": "User Launch Agent PLIST - Potential persistence mechanism"},
                {"pattern": r"\\b/Library/LaunchAgents/.*\\.plist\\b", "description": "System Launch Agent PLIST - Potential persistence mechanism"},
                {"pattern": r"\\b~/Library/LaunchDaemons/.*\\.plist\\b", "description": "User Launch Daemon PLIST - Potential persistence mechanism"},
                {"pattern": r"\\b/Library/LaunchDaemons/.*\\.plist\\b", "description": "System Launch Daemon PLIST - Potential persistence mechanism"},
                {"pattern": r"\\b/System/Library/LaunchAgents/.*\\.plist\\b", "description": "System Library Launch Agent PLIST - Potential persistence mechanism"},
                {"pattern": r"\\b/System/Library/LaunchDaemons/.*\\.plist\\b", "description": "System Library Launch Daemon PLIST - Potential persistence mechanism"},
            ],
            "Firewall Configuration": [
                {"pattern": r"\\bpfctl\\b", "description": "PF firewall control - Potential firewall manipulation"},
                {"pattern": r"\\bpfctl\\b.*\\benable\\b", "description": "PF enable - Potential firewall manipulation"},
                {"pattern": r"\\bpfctl\\b.*\\bdisable\\b", "description": "PF disable - Potential firewall manipulation"},
                {"pattern": r"\\bpfctl\\b.*\\bload\\b", "description": "PF load - Potential firewall manipulation"},
                {"pattern": r"\\bpfctl\\b.*\\breload\\b", "description": "PF reload - Potential firewall manipulation"},
                {"pattern": r"\\bpfctl\\b.*\\bshow\\b", "description": "PF show - Potential firewall manipulation"},
                {"pattern": r"\\bpfctl\\b.*\\bstatus\\b", "description": "PF status - Potential firewall manipulation"},
                {"pattern": r"\\bpfctl\\b.*\\btest\\b", "description": "PF test - Potential firewall manipulation"},
                {"pattern": r"\\bpfctl\\b.*\\block\\b", "description": "PF block rule - Potential firewall manipulation"},
                {"pattern": r"\\bpfctl\\b.*\\pass\\b", "description": "PF pass rule - Potential firewall manipulation"},
                {"pattern": r"\\b/etc/pf\\.conf\\b", "description": "PF configuration file - Potential firewall manipulation"},
                {"pattern": r"\\b/etc/pf\\.anchors/\\b", "description": "PF anchors directory - Potential firewall manipulation"},
                {"pattern": r"\\b/etc/pf\\.tables/\\b", "description": "PF tables directory - Potential firewall manipulation"},
                {"pattern": r"\\b/etc/pf\\.rules/\\b", "description": "PF rules directory - Potential firewall manipulation"},
                {"pattern": r"\\b/etc/pf\\.filters/\\b", "description": "PF filters directory - Potential firewall manipulation"},
                {"pattern": r"\\b/etc/pf\\.nat/\\b", "description": "PF NAT directory - Potential firewall manipulation"},
                {"pattern": r"\\b/etc/pf\\.options/\\b", "description": "PF options directory - Potential firewall manipulation"},
                {"pattern": r"\\b/etc/pf\\.params/\\b", "description": "PF params directory - Potential firewall manipulation"},
                {"pattern": r"\\b/etc/pf\\.macros/\\b", "description": "PF macros directory - Potential firewall manipulation"},
                {"pattern": r"\\b/etc/pf\\.variables/\\b", "description": "PF variables directory - Potential firewall manipulation"},
            ]
        }
    }

    try:
        # Get the current rules.json file
        current_rules = repo.get_contents("rules.json", ref="main")
        current_rules_content = current_rules.decoded_content.decode('utf-8')
        rules_data = json.loads(current_rules_content)
        
        # Add the new Linux rules
        for category, rules in additional_os_rules["Linux"].items():
            if category not in rules_data["Linux"]:
                rules_data["Linux"][category] = []
            
            for rule in rules:
                # Check if the rule already exists to avoid duplicates
                exists = False
                for existing_rule in rules_data["Linux"][category]:
                    if existing_rule["pattern"] == rule["pattern"]:
                        exists = True
                        break
                
                if not exists:
                    rules_data["Linux"][category].append(rule)
        
        # Add the new macOS rules
        for category, rules in additional_os_rules["macOS"].items():
            if category not in rules_data["macOS"]:
                rules_data["macOS"][category] = []
            
            for rule in rules:
                # Check if the rule already exists to avoid duplicates
                exists = False
                for existing_rule in rules_data["macOS"][category]:
                    if existing_rule["pattern"] == rule["pattern"]:
                        exists = True
                        break
                
                if not exists:
                    rules_data["macOS"][category].append(rule)
        
        # Convert back to JSON string
        updated_rules_content = json.dumps(rules_data, indent=2)
        
        # Update the rules.json file
        repo.update_file(
            path="rules.json",
            message="Add missing macOS and Linux persistence and firewall rules",
            content=updated_rules_content,
            sha=current_rules.sha,
            branch="main"
        )
        
        total_new_rules = sum(len(rules) for rules in additional_os_rules["Linux"].values()) + sum(len(rules) for rules in additional_os_rules["macOS"].values())
        print(f"✅ Successfully added {total_new_rules} macOS and Linux persistence and firewall rules to the repository")
        
    except Exception as e:
        print(f"❌ Error updating rules.json: {e}")

    print("\n✅ Completed adding missing macOS and Linux persistence and firewall rules.")

if __name__ == "__main__":
    main()