"""
Threat Intelligence Module for Command Line Analyzer

This module provides integration with threat intelligence feeds and
MITRE ATT&CK framework mappings to enhance detection capabilities.
"""

import json
import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
import requests
from pathlib import Path


class Tactic(Enum):
    """MITRE ATT&CK Tactics"""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


@dataclass
class ThreatIntelEntry:
    """Represents a threat intelligence entry"""
    technique_id: str
    technique_name: str
    tactic: Tactic
    description: str
    platforms: List[str]
    detection_details: str
    references: List[str]


class ThreatIntelligenceProvider:
    """Base class for threat intelligence providers"""
    
    def __init__(self):
        self.threat_database = {}
        self.mitre_mappings = {}
    
    def load_mitre_mappings(self, mapping_file: str = "mitre_mappings.json"):
        """Load MITRE ATT&CK mappings from file"""
        try:
            with open(mapping_file, 'r') as f:
                mappings = json.load(f)
                self.mitre_mappings = mappings
        except FileNotFoundError:
            # Create default mappings if file doesn't exist
            self._create_default_mappings()
    
    def _create_default_mappings(self):
        """Create default MITRE ATT&CK mappings"""
        self.mitre_mappings = {
            # User account creation
            "User Account Creation": {
                "technique_id": "T1136.001",
                "technique_name": "Create Account: Local Account",
                "tactic": Tactic.PERSISTENCE.value,
                "description": "Adversaries may create a local account to maintain access to victim systems.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1136/001/"]
            },
            # Scheduled task creation
            "Scheduled Task Creation": {
                "technique_id": "T1053.005",
                "technique_name": "Scheduled Task/Job: Scheduled Task",
                "tactic": Tactic.PERSISTENCE.value,
                "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
                "platforms": ["Windows"],
                "references": ["https://attack.mitre.org/techniques/T1053/005/"]
            },
            # Registry modification
            "Registry Modification: Auto-run Key": {
                "technique_id": "T1547.001",
                "technique_name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                "tactic": Tactic.PERSISTENCE.value,
                "description": "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.",
                "platforms": ["Windows"],
                "references": ["https://attack.mitre.org/techniques/T1547/001/"]
            },
            # PowerShell execution policy bypass
            "PowerShell Execution Policy Bypass": {
                "technique_id": "T1059.001",
                "technique_name": "Command and Scripting Interpreter: PowerShell",
                "tactic": Tactic.EXECUTION.value,
                "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
                "platforms": ["Windows"],
                "references": ["https://attack.mitre.org/techniques/T1059/001/"]
            },
            # Credential dumping
            "Credential Dumping Tool Activity (Mimikatz-like)": {
                "technique_id": "T1003.001",
                "technique_name": "OS Credential Dumping: LSASS Memory",
                "tactic": Tactic.CREDENTIAL_ACCESS.value,
                "description": "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).",
                "platforms": ["Windows"],
                "references": ["https://attack.mitre.org/techniques/T1003/001/"]
            },
            # File download
            "File Download (PowerShell WebRequest)": {
                "technique_id": "T1105",
                "technique_name": "Ingress Tool Transfer",
                "tactic": Tactic.COMMAND_AND_CONTROL.value,
                "description": "Adversaries may transfer tools or other files from an external system.",
                "platforms": ["Windows"],
                "references": ["https://attack.mitre.org/techniques/T1105/"]
            },
            # Network discovery
            "Network Path Tracing": {
                "technique_id": "T1018",
                "technique_name": "Remote System Discovery",
                "tactic": Tactic.DISCOVERY.value,
                "description": "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1018/"]
            },
            # System info enumeration
            "System Information Enumeration": {
                "technique_id": "T1082",
                "technique_name": "System Information Discovery",
                "tactic": Tactic.DISCOVERY.value,
                "description": "An adversary may attempt to get detailed information about the operating system and hardware.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1082/"]
            },
            # Service manipulation
            "Windows Service Creation": {
                "technique_id": "T1569.002",
                "technique_name": "System Services: Service Execution",
                "tactic": Tactic.EXECUTION.value,
                "description": "Adversaries may abuse the Windows service control manager to execute malicious commands or payloads.",
                "platforms": ["Windows"],
                "references": ["https://attack.mitre.org/techniques/T1569/002/"]
            },
            # Firewall configuration
            "Windows Firewall Configuration": {
                "technique_id": "T1562.004",
                "technique_name": "Impair Defenses: Disable or Modify System Firewall",
                "tactic": Tactic.DEFENSE_EVASION.value,
                "description": "Adversaries may disable or modify system firewalls to bypass controls limiting network usage.",
                "platforms": ["Windows"],
                "references": ["https://attack.mitre.org/techniques/T1562/004/"]
            },
            # Backup manipulation
            "Volume Shadow Copy Deletion": {
                "technique_id": "T1490",
                "technique_name": "Inhibit System Recovery",
                "tactic": Tactic.IMPACT.value,
                "description": "Adversaries may delete or remove built-in operating system data and turn off services designed to aid in recovery to prevent restoration.",
                "platforms": ["Windows"],
                "references": ["https://attack.mitre.org/techniques/T1490/"]
            },
            # Group member addition
            "Local Group Member Added": {
                "technique_id": "T1078.003",
                "technique_name": "Valid Accounts: Local Accounts",
                "tactic": Tactic.PERSISTENCE.value,
                "description": "Adversaries may add adversaries to local groups to enable access to systems.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1078/003/"]
            },
            # Process termination
            "Process Termination": {
                "technique_id": "T1562.006",
                "technique_name": "Impair Defenses: Indicator Blocking",
                "tactic": Tactic.DEFENSE_EVASION.value,
                "description": "Adversaries may block indicators from being gathered by security tools.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1562/006/"]
            },
            # Lateral movement
            "Impacket Tool Execution": {
                "technique_id": "T1021.002",
                "technique_name": "Remote Services: SMB/Windows Admin Shares",
                "tactic": Tactic.LATERAL_MOVEMENT.value,
                "description": "Adversaries may use Valid Accounts to log into a computer using the Server Message Block (SMB) protocol.",
                "platforms": ["Windows"],
                "references": ["https://attack.mitre.org/techniques/T1021/002/"]
            },
            # UAC bypass check
            "UAC Policy Check via Registry": {
                "technique_id": "T1518.001",
                "technique_name": "Software Discovery: Security Software Discovery",
                "tactic": Tactic.DISCOVERY.value,
                "description": "Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors.",
                "platforms": ["Windows"],
                "references": ["https://attack.mitre.org/techniques/T1518/001/"]
            },
            # Log clearing
            "Event Log Cleared": {
                "technique_id": "T1070.001",
                "technique_name": "Indicator Removal: Clear Windows Event Logs",
                "tactic": Tactic.DEFENSE_EVASION.value,
                "description": "Adversaries may clear Windows Event Logs to hide the activity of an intrusion.",
                "platforms": ["Windows"],
                "references": ["https://attack.mitre.org/techniques/T1070/001/"]
            },
            # Password cracking
            "Password Cracking Tool (John the Ripper)": {
                "technique_id": "T1110.001",
                "technique_name": "Brute Force: Password Guessing",
                "tactic": Tactic.CREDENTIAL_ACCESS.value,
                "description": "Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts.",
                "platforms": ["Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1110/001/"]
            },
            # Network scanning
            "Network Port Scanning (nmap)": {
                "technique_id": "T1046",
                "technique_name": "Network Service Scanning",
                "tactic": Tactic.DISCOVERY.value,
                "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
                "platforms": ["Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1046/"]
            },
            # macOS security check
            "System Integrity Protection Status Check": {
                "technique_id": "T1518.001",
                "technique_name": "Software Discovery: Security Software Discovery",
                "tactic": Tactic.DISCOVERY.value,
                "description": "Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors.",
                "platforms": ["macOS"],
                "references": ["https://attack.mitre.org/techniques/T1518/001/"]
            },
            # New curl-related rules
            "File Download (curl)": {
                "technique_id": "T1105",
                "technique_name": "Ingress Tool Transfer",
                "tactic": Tactic.COMMAND_AND_CONTROL.value,
                "description": "Adversaries may transfer tools or other files from an external system.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1105/"]
            },
            "Secure File Download (curl)": {
                "technique_id": "T1105",
                "technique_name": "Ingress Tool Transfer",
                "tactic": Tactic.COMMAND_AND_CONTROL.value,
                "description": "Adversaries may transfer tools or other files from an external system using secure connections.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1105/"]
            },
            "HTTP POST Request (curl)": {
                "technique_id": "T1071.001",
                "technique_name": "Application Layer Protocol: Web Protocols",
                "tactic": Tactic.COMMAND_AND_CONTROL.value,
                "description": "Adversaries may communicate using application layer protocols associated with web traffic to elude firewalls.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1071/001/"]
            },
            "Data Upload via curl (POST data)": {
                "technique_id": "T1041",
                "technique_name": "Exfiltration Over C2 Channel",
                "tactic": Tactic.EXFILTRATION.value,
                "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1041/"]
            },
            "File Upload via curl (POST file)": {
                "technique_id": "T1041",
                "technique_name": "Exfiltration Over C2 Channel",
                "tactic": Tactic.EXFILTRATION.value,
                "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1041/"]
            },
            "Authentication Credentials in curl": {
                "technique_id": "T1552.001",
                "technique_name": "Unsecured Credentials: Credentials In Files",
                "tactic": Tactic.CREDENTIAL_ACCESS.value,
                "description": "Adversaries may search for insecurely stored credentials in files and command history.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1552/001/"]
            },
            "Direct Execution of curl Output": {
                "technique_id": "T1059.007",
                "technique_name": "Command and Scripting Interpreter: JavaScript",
                "tactic": Tactic.EXECUTION.value,
                "description": "Adversaries may abuse various command interpreters to execute commands.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1059/007/"]
            },
            "Executable Download (curl)": {
                "technique_id": "T1204.002",
                "technique_name": "User Execution: Malicious File",
                "tactic": Tactic.EXECUTION.value,
                "description": "An adversary may rely upon a user clicking a malicious link or file to execute an attack.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1204/002/"]
            },
            "HTTP GET Request (curl)": {
                "technique_id": "T1071.001",
                "technique_name": "Application Layer Protocol: Web Protocols",
                "tactic": Tactic.COMMAND_AND_CONTROL.value,
                "description": "Adversaries may communicate using application layer protocols associated with web traffic to elude firewalls.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1071/001/"]
            },
            "HTTP HEAD Request (curl)": {
                "technique_id": "T1071.001",
                "technique_name": "Application Layer Protocol: Web Protocols",
                "tactic": Tactic.COMMAND_AND_CONTROL.value,
                "description": "Adversaries may communicate using application layer protocols associated with web traffic to elude firewalls.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1071/001/"]
            },
            "Follow Redirects (curl)": {
                "technique_id": "T1071.001",
                "technique_name": "Application Layer Protocol: Web Protocols",
                "tactic": Tactic.COMMAND_AND_CONTROL.value,
                "description": "Adversaries may communicate using application layer protocols associated with web traffic to elude firewalls.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1071/001/"]
            },
            "HTTP POST Request (curl)": {
                "technique_id": "T1071.001",
                "technique_name": "Application Layer Protocol: Web Protocols",
                "tactic": Tactic.COMMAND_AND_CONTROL.value,
                "description": "Adversaries may communicate using application layer protocols associated with web traffic to elude firewalls.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1071/001/"]
            },
            "HTTP PUT Request (curl)": {
                "technique_id": "T1071.001",
                "technique_name": "Application Layer Protocol: Web Protocols",
                "tactic": Tactic.COMMAND_AND_CONTROL.value,
                "description": "Adversaries may communicate using application layer protocols associated with web traffic to elude firewalls.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1071/001/"]
            },
            "HTTP DELETE Request (curl)": {
                "technique_id": "T1071.001",
                "technique_name": "Application Layer Protocol: Web Protocols",
                "tactic": Tactic.COMMAND_AND_CONTROL.value,
                "description": "Adversaries may communicate using application layer protocols associated with web traffic to elude firewalls.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1071/001/"]
            },
            "Authorization Header in curl": {
                "technique_id": "T1566",
                "technique_name": "Phishing",
                "tactic": Tactic.INITIAL_ACCESS.value,
                "description": "Adversaries may send messages with malicious links or attachments from a seemingly trusted source.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1566/"]
            },
            "Cookie Header in curl": {
                "technique_id": "T1556",
                "technique_name": "Modify Authentication Process",
                "tactic": Tactic.CREDENTIAL_ACCESS.value,
                "description": "Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1556/"]
            },
            "Follow Redirects (curl)": {
                "technique_id": "T1071.001",
                "technique_name": "Application Layer Protocol: Web Protocols",
                "tactic": Tactic.COMMAND_AND_CONTROL.value,
                "description": "Adversaries may communicate using application layer protocols associated with web traffic to elude firewalls.",
                "platforms": ["Windows", "Linux", "macOS"],
                "references": ["https://attack.mitre.org/techniques/T1071/001/"]
            }
        }
    
    def get_threat_intel_for_detection(self, detection_description: str) -> Optional[ThreatIntelEntry]:
        """Get threat intelligence for a specific detection"""
        if detection_description in self.mitre_mappings:
            mapping = self.mitre_mappings[detection_description]
            return ThreatIntelEntry(
                technique_id=mapping["technique_id"],
                technique_name=mapping["technique_name"],
                tactic=Tactic(mapping["tactic"]),
                description=mapping["description"],
                platforms=mapping["platforms"],
                detection_details=detection_description,
                references=mapping["references"]
            )
        return None
    
    def enrich_analysis_result(self, analysis_result: str) -> str:
        """Enrich an analysis result with threat intelligence"""
        # Extract the description part from the analysis result
        # Format: "Description | Category: CategoryName | OS: OSName"
        parts = analysis_result.split(" | ")
        if len(parts) >= 3:
            description = parts[0]
            category = parts[1].replace("Category: ", "")
            os_info = parts[2].replace("OS: ", "")
            
            # Get threat intelligence for this detection
            threat_entry = self.get_threat_intel_for_detection(description)
            if threat_entry:
                enriched_result = (
                    f"{analysis_result} | MITRE: {threat_entry.technique_id} ({threat_entry.technique_name}) | "
                    f"Tactic: {threat_entry.tactic.name} | Confidence: High"
                )
                return enriched_result
        
        return analysis_result  # Return original if no enrichment available
    
    def get_ttp_summary(self, analysis_results: List[str]) -> Dict:
        """Get a summary of tactics, techniques, and procedures detected"""
        ttp_summary = {
            "tactics": {},
            "techniques": {},
            "counts": {}
        }

        for result in analysis_results:
            threat_entry = self.get_threat_intel_for_detection(result.split(" | ")[0])
            if threat_entry:
                # Count tactics
                tactic_name = threat_entry.tactic.name
                ttp_summary["tactics"][tactic_name] = ttp_summary["tactics"].get(tactic_name, 0) + 1

                # Count techniques
                tech_key = f"{threat_entry.technique_id}: {threat_entry.technique_name}"
                ttp_summary["techniques"][tech_key] = ttp_summary["techniques"].get(tech_key, 0) + 1

        return ttp_summary

    def map_attack_chains_to_threat_actors(self, attack_chains: List[Dict]) -> Dict:
        """Map attack chains to known threat actor patterns"""
        threat_actor_mapping = {
            # Ransomware patterns
            "DISABLE_DEFENSES_THEN_DELETE_SHADOWS": {
                "associated_threat_actors": ["Conti", "REvil", "Ryuk", "LockBit"],
                "ttps": ["T1562.001", "T1490", "T1089"],  # Impair Defenses, Inhibit System Recovery
                "description": "Disabling security software followed by deleting backups/shadow copies"
            },
            "USER_ENUM_THEN_CREATION_THEN_PERSISTENCE": {
                "associated_threat_actors": ["APT29", "APT28", "FIN6"],
                "ttps": ["T1087", "T1136", "T1547"],  # Account Discovery, Create Account, Event Triggered Execution
                "description": "User enumeration followed by account creation and persistence mechanism setup"
            },
            "RECON_THEN_LATERAL_MOVEMENT": {
                "associated_threat_actors": ["APT1", "APT41", "Lazarus"],
                "ttps": ["T1082", "T1018", "T1021"],  # System Info Discovery, Remote System Discovery, Remote Services
                "description": "System reconnaissance followed by lateral movement attempts"
            },
            "CREDENTIAL_ACCESS_THEN_EXFILTRATION": {
                "associated_threat_actors": ["APT3", "APT18", "Carbanak"],
                "ttps": ["T1003", "T1074", "T1041"],  # OS Credential Dumping, Data Staged, Exfiltration Over C2 Channel
                "description": "Credential access followed by data staging and exfiltration"
            }
        }

        mapped_chains = {
            "identified_threat_patterns": [],
            "associated_threat_actors": set(),
            "recommended_actions": []
        }

        for chain in attack_chains:
            chain_commands = [cmd.lower() for cmd in chain['steps']]
            
            # Check for ransomware pattern: disable defenses then delete shadows
            has_defense_disable = any('defender' in cmd or 'security' in cmd for cmd in chain_commands)
            has_shadow_delete = any('vssadmin' in cmd and 'delete' in cmd for cmd in chain_commands)
            has_recovery_disable = any('bcdedit' in cmd and 'recovery' in cmd for cmd in chain_commands)
            
            if (has_defense_disable or has_recovery_disable) and has_shadow_delete:
                mapped_chains["identified_threat_patterns"].append({
                    "pattern": "DISABLE_DEFENSES_THEN_DELETE_SHADOWS",
                    "details": threat_actor_mapping["DISABLE_DEFENSES_THEN_DELETE_SHADOWS"],
                    "chain": chain,
                    "confidence": "HIGH"
                })
                mapped_chains["associated_threat_actors"].update(
                    threat_actor_mapping["DISABLE_DEFENSES_THEN_DELETE_SHADOWS"]["associated_threat_actors"]
                )
                
            # Check for user enumeration then creation then persistence
            has_user_enum = any('net user' in cmd and '/domain' in cmd for cmd in chain_commands)
            has_user_creation = any('net user' in cmd and '/add' in cmd for cmd in chain_commands)
            has_persistence = any('reg add' in cmd and 'run' in cmd for cmd in chain_commands)
            
            if has_user_enum and has_user_creation and has_persistence:
                mapped_chains["identified_threat_patterns"].append({
                    "pattern": "USER_ENUM_THEN_CREATION_THEN_PERSISTENCE",
                    "details": threat_actor_mapping["USER_ENUM_THEN_CREATION_THEN_PERSISTENCE"],
                    "chain": chain,
                    "confidence": "MEDIUM"
                })
                mapped_chains["associated_threat_actors"].update(
                    threat_actor_mapping["USER_ENUM_THEN_CREATION_THEN_PERSISTENCE"]["associated_threat_actors"]
                )

        # Add recommended actions based on findings
        if "Conti" in mapped_chains["associated_threat_actors"] or "REvil" in mapped_chains["associated_threat_actors"]:
            mapped_chains["recommended_actions"].extend([
                "Isolate affected systems immediately",
                "Check for lateral movement indicators",
                "Review domain controller logs for unusual authentication patterns",
                "Validate backup integrity and availability"
            ])
        
        if "APT29" in mapped_chains["associated_threat_actors"]:
            mapped_chains["recommended_actions"].extend([
                "Review Office document execution logs",
                "Check for PowerShell obfuscation techniques",
                "Validate email gateway logs for spear-phishing campaigns"
            ])

        # Convert set to list for JSON serialization
        mapped_chains["associated_threat_actors"] = list(mapped_chains["associated_threat_actors"])
        
        return mapped_chains


# Example usage
if __name__ == "__main__":
    # Initialize threat intelligence provider
    ti_provider = ThreatIntelligenceProvider()
    ti_provider.load_mitre_mappings()
    
    # Example analysis result
    sample_result = "User Account Creation | Category: User and Group Management | OS: Windows"
    
    # Enrich with threat intelligence
    enriched_result = ti_provider.enrich_analysis_result(sample_result)
    print("Original:", sample_result)
    print("Enriched:", enriched_result)
    
    # Get TTP summary
    sample_results = [
        "User Account Creation | Category: User and Group Management | OS: Windows",
        "Scheduled Task Creation | Category: Scheduled Tasks | OS: Windows",
        "Registry Modification: Auto-run Key | Category: Windows Registry Modification | OS: Windows"
    ]
    
    ttp_summary = ti_provider.get_ttp_summary(sample_results)
    print("\nTTP Summary:", json.dumps(ttp_summary, indent=2))