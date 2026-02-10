"""
Log Analyzer: Command-line rule matcher with Excel-safe CSV output.

Features:
- Loads hierarchical rules.json (OS -> Category -> Rules).
- Validates regex patterns.
- Sanitizes Unicode to avoid "Â" artifacts in Excel.
- Reads CSV with utf-8-sig; writes CSV with utf-8-sig (Excel detects UTF-8).
- Optionally writes .xlsx (requires openpyxl).
- Includes performance metrics and benchmarking.
- Integrates with threat intelligence feeds.
- Performs behavioral analysis for anomaly detection.

Author: Rohit
"""

import json
import re
import sys
import time
import unicodedata
from pathlib import Path
from collections import defaultdict

import pandas as pd

# Import threat intelligence module
try:
    from threat_intel import ThreatIntelligenceProvider
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    THREAT_INTEL_AVAILABLE = False
    print("⚠️  Threat intelligence module not found. Install with: pip install -e . (if available)")

# Import behavioral analysis module
try:
    from behavioral_analyzer import BehavioralAnalyzer
    BEHAVIORAL_ANALYSIS_AVAILABLE = True
except ImportError:
    BEHAVIORAL_ANALYSIS_AVAILABLE = False
    print("⚠️  Behavioral analysis module not found. Install with: pip install -e . (if available)")


# ============ CONFIGURATION ============

# Input CSV containing a 'CommandLine' column (case-insensitive)
INPUT_CSV_PATH = r"demo_ransomware_attack.csv"  # Updated to use demo data

# Output CSV/XLSX
OUTPUT_CSV_PATH = r"Commands_analyzed.csv"
OUTPUT_XLSX_PATH = r"Commands_analyzed.xlsx"  # optional

# Hierarchical rules file (the JSON we built together)
RULES_JSON_PATH = r"rules.json"

# Also create an XLSX alongside the CSV (Excel-native, avoids encoding quirks)
WRITE_XLSX = True  # set to False if you only want CSV

# Enable threat intelligence enrichment
ENABLE_THREAT_INTEL = True

# Enable behavioral analysis
ENABLE_BEHAVIORAL_ANALYSIS = True


# ============ UTILITIES ============

def sanitize_text(s: str) -> str:
    """
    Normalize text to remove common Unicode artifacts that Excel/legacy decoders
    render as 'Â' or similar. Also replaces smart dashes/nbsp with ASCII.
    """
    if not isinstance(s, str):
        s = str(s)
    # Replace common culprits
    s = s.replace('\u00A0', ' ')   # NBSP -> space
    s = s.replace('–', '-')        # en dash -> hyphen
    s = s.replace('—', '-')        # em dash -> hyphen
    # Normalize to a canonical form
    return unicodedata.normalize('NFKC', s)


def clean_path(p: str) -> Path:
    """
    Strip stray quotes/whitespace and resolve to an absolute Path.
    """
    cleaned = str(p).strip().strip('"').strip("'")
    return Path(cleaned).expanduser().resolve()


# ============ RULES LOADING & VALIDATION ============

def load_rules(rules_path: str | Path) -> dict:
    """
    Load hierarchical JSON rules (OS -> Category -> [ {pattern, description} ]).
    Validates structure and compiles regex patterns to fail fast on mistakes.
    """
    path = clean_path(rules_path)
    if not path.exists():
        raise FileNotFoundError(f"Rules file not found: {path}")

    with path.open('r', encoding='utf-8') as f:
        data = json.load(f)

    # Basic structure validation + regex compilation
    for os_name, categories in data.items():
        if str(os_name).startswith("_"):  # skip the _schema block
            continue
        if not isinstance(categories, dict):
            raise ValueError(f"Expected dict of categories under '{os_name}', got {type(categories)}")

        for category, rules in categories.items():
            if not isinstance(rules, list):
                raise ValueError(f"Expected list of rules under '{os_name}' -> '{category}', got {type(rules)}")

            for idx, rule in enumerate(rules, 1):
                if not isinstance(rule, dict):
                    raise ValueError(f"Rule #{idx} under '{os_name}' -> '{category}' must be an object/dict")
                if "pattern" not in rule or "description" not in rule:
                    raise ValueError(f"Missing 'pattern' or 'description' in rule #{idx} under '{os_name}' -> '{category}'")
                try:
                    re.compile(rule["pattern"])
                except re.error as e:
                    raise ValueError(
                        f"Invalid regex in '{os_name}' -> '{category}' -> rule #{idx} "
                        f"({rule.get('description','<no desc>')}): {e}"
                    )
    return data


def make_analyzer(rules_data: dict):
    """
    Returns a function analyze_command(command: str) -> str that iterates the
    OS -> Category -> Rules structure and returns the first matching description.
    Also tracks performance metrics.
    """
    # Initialize metrics tracking
    metrics = {
        'total_commands': 0,
        'matched_commands': 0,
        'unknown_commands': 0,
        'rule_matches': defaultdict(int),
        'processing_times': [],
        'rule_performance': defaultdict(float)  # Time spent matching each rule
    }
    
    # Initialize threat intelligence if enabled
    threat_intel_provider = None
    if ENABLE_THREAT_INTEL and THREAT_INTEL_AVAILABLE:
        threat_intel_provider = ThreatIntelligenceProvider()
        threat_intel_provider.load_mitre_mappings()
    
    def analyze_command(command: str) -> str:
        start_time = time.time()
        cmd = sanitize_text(command).lower()
        metrics['total_commands'] += 1
        
        for os_name, categories in rules_data.items():
            if str(os_name).startswith("_"):
                continue
            for category, rules in categories.items():
                for rule in rules:
                    pattern = rule["pattern"]
                    desc = rule["description"]
                    
                    rule_start = time.time()
                    match_result = re.search(pattern, cmd)
                    rule_time = time.time() - rule_start
                    metrics['rule_performance'][f"{os_name}:{category}:{desc}"] += rule_time
                    
                    if match_result:
                        result = f"{desc} | Category: {category} | OS: {os_name}"
                        
                        # Enrich with threat intelligence if available
                        if threat_intel_provider:
                            result = threat_intel_provider.enrich_analysis_result(result)
                        
                        metrics['matched_commands'] += 1
                        metrics['rule_matches'][f"{os_name}:{category}:{desc}"] += 1
                        total_time = time.time() - start_time
                        metrics['processing_times'].append(total_time)
                        return sanitize_text(result)
        
        metrics['unknown_commands'] += 1
        total_time = time.time() - start_time
        metrics['processing_times'].append(total_time)
        return "Unknown Activity"
    
    # Attach metrics to the function for later retrieval
    analyze_command.metrics = metrics
    return analyze_command


def print_metrics(analyze_func):
    """Print detailed performance metrics."""
    metrics = analyze_func.metrics
    
    print("\n" + "="*60)
    print("PERFORMANCE METRICS")
    print("="*60)
    
    print(f"Total Commands Processed: {metrics['total_commands']}")
    print(f"Matched Commands: {metrics['matched_commands']}")
    print(f"Unknown Commands: {metrics['unknown_commands']}")
    
    if metrics['total_commands'] > 0:
        match_rate = (metrics['matched_commands'] / metrics['total_commands']) * 100
        print(f"Match Rate: {match_rate:.2f}%")
    
    if metrics['processing_times']:
        avg_processing_time = sum(metrics['processing_times']) / len(metrics['processing_times'])
        total_processing_time = sum(metrics['processing_times'])
        print(f"Average Processing Time per Command: {avg_processing_time:.6f}s")
        print(f"Total Processing Time: {total_processing_time:.4f}s")
    
    print("\nTop 10 Most Used Rules:")
    sorted_rules = sorted(metrics['rule_matches'].items(), key=lambda x: x[1], reverse=True)[:10]
    for rule, count in sorted_rules:
        print(f"  {count:4d} matches - {rule}")
    
    print("\nTop 10 Slowest Rules (by cumulative time):")
    sorted_performance = sorted(metrics['rule_performance'].items(), key=lambda x: x[1], reverse=True)[:10]
    for rule, time_spent in sorted_performance:
        print(f"  {time_spent:.6f}s - {rule}")
    
    print("="*60)


def generate_narrative_summary(df: pd.DataFrame) -> str:
    """
    Generate a narrative summary of the analysis results in paragraph form.
    """
    # Count total commands analyzed
    total_commands = len(df)
    
    # Count known/unknown activities
    known_activities = df[df['Analysis'] != 'Unknown Activity']
    unknown_activities = df[df['Analysis'] == 'Unknown Activity']
    known_count = len(known_activities)
    unknown_count = len(unknown_activities)
    
    # Get activity counts by description (cleaning MITRE info)
    clean_analysis = known_activities['Analysis'].apply(lambda x: x.split(' | ')[0] if ' | ' in x else x)
    activity_counts = clean_analysis.value_counts()
    
    # Determine the most common activities
    if len(activity_counts) > 0:
        top_desc = activity_counts.index[0]
        top_count = activity_counts.iloc[0]
        
        # Get second most common if available
        if len(activity_counts) > 1:
            second_desc = activity_counts.index[1]
            second_count = activity_counts.iloc[1]
            top_activities = f"'{top_desc}' (occurring {top_count} times) and '{second_desc}' (occurring {second_count} times)"
        else:
            top_activities = f"'{top_desc}' occurring {top_count} times"
    else:
        top_desc = "no specific patterns"
        top_activities = "no specific patterns"
    
    # Determine severity based on number of known activities
    if known_count == 0:
        severity_level = "no notable findings"
        concern_level = "low"
    elif known_count <= 5:
        severity_level = "a few suspicious activities"
        concern_level = "relatively low concern"
    elif known_count <= 20:
        severity_level = "several suspicious activities"
        concern_level = "moderate concern"
    elif known_count <= 50:
        severity_level = "multiple suspicious activities"
        concern_level = "moderate to high concern"
    else:
        severity_level = "numerous suspicious activities"
        concern_level = "high concern"
    
    # Identify different types of threats
    execution_related = ['execution', 'powershell', 'script', 'process', 'dll', 'hta', 'wsh']
    network_related = ['network', 'port', 'ipconfig', 'nbtstat', 'arp', 'netsh', 'discovery', 'enumeration']
    persistence_related = ['persistence', 'scheduled', 'autorun', 'registry', 'startup', 'service']
    credential_related = ['credential', 'mimikatz', 'password', 'hash', 'authentication', 'token']
    defense_evasion = ['evasion', 'bypass', 'defender', 'firewall', 'log', 'event']
    lateral_related = ['lateral', 'psexec', 'wmiexec', 'smbexec', 'remote', 'session']
    
    threat_types = []
    if any(any(keyword in analysis.lower() for keyword in execution_related) for analysis in known_activities['Analysis']):
        threat_types.append("execution-related")
    if any(any(keyword in analysis.lower() for keyword in network_related) for analysis in known_activities['Analysis']):
        threat_types.append("network reconnaissance")
    if any(any(keyword in analysis.lower() for keyword in persistence_related) for analysis in known_activities['Analysis']):
        threat_types.append("persistence mechanisms")
    if any(any(keyword in analysis.lower() for keyword in credential_related) for analysis in known_activities['Analysis']):
        threat_types.append("credential access")
    if any(any(keyword in analysis.lower() for keyword in defense_evasion) for analysis in known_activities['Analysis']):
        threat_types.append("defense evasion")
    if any(any(keyword in analysis.lower() for keyword in lateral_related) for analysis in known_activities['Analysis']):
        threat_types.append("lateral movement")
    
    threat_summary = ""
    if threat_types:
        if len(threat_types) == 1:
            threat_summary = f" The detected activities suggest {threat_types[0]} techniques."
        elif len(threat_types) == 2:
            threat_summary = f" The detected activities suggest both {threat_types[0]} and {threat_types[1]} techniques."
        else:
            threat_summary = f" The detected activities suggest {', '.join(threat_types[:-1])}, and {threat_types[-1]} techniques."
    
    # Check for high-risk activities
    high_risk_keywords = ['credential', 'mimikatz', 'exfiltration', 'lateral', 'persistence', 'privilege escalation', 'defense evasion', 'volume shadow copy', 'event log cleared']
    high_risk_found = any(
        any(keyword in analysis.lower() for keyword in high_risk_keywords)
        for analysis in known_activities['Analysis']
    )
    
    high_risk_indicator = ""
    if high_risk_found:
        high_risk_indicator = " Several high-risk activities were identified, indicating potential advanced threats. "
    
    # Construct the narrative summary
    narrative = (
        f"The analysis of {total_commands} command line entries revealed {severity_level}. "
        f"The most commonly observed activities were {top_activities}. "
        f"A total of {known_count} commands matched known suspicious patterns, while {unknown_count} "
        f"commands did not match any defined rules. The overall threat level appears to be {concern_level}."
        f"{threat_summary}{high_risk_indicator}"
        f"These findings warrant further investigation by security personnel."
    )
    
    return narrative


def perform_behavioral_analysis(df: pd.DataFrame):
    """Perform behavioral analysis on the analyzed data"""
    if not BEHAVIORAL_ANALYSIS_AVAILABLE:
        print("⚠️  Behavioral analysis not available. Skipping...")
        return df

    print("\n🔍 Performing Behavioral Analysis...")
    behavioral_analyzer = BehavioralAnalyzer()

    # Perform anomaly detection
    analyzed_df = behavioral_analyzer.detect_anomalies(df)

    # Generate behavioral report
    report = behavioral_analyzer.generate_behavioral_report(analyzed_df)
    print("\n" + report)

    # If threat intelligence is available, map attack chains to threat actors
    if ENABLE_THREAT_INTEL and THREAT_INTEL_AVAILABLE:
        try:
            from threat_intel import ThreatIntelligenceProvider
            threat_intel_provider = ThreatIntelligenceProvider()
            threat_intel_provider.load_mitre_mappings()
            
            # Get attack chains from the behavioral analyzer
            attack_chains = behavioral_analyzer.identify_attack_chains(analyzed_df)
            
            if attack_chains:
                print("\n🌐 Threat Actor Attribution Analysis:")
                threat_mapping = threat_intel_provider.map_attack_chains_to_threat_actors(attack_chains)
                
                if threat_mapping["identified_threat_patterns"]:
                    print(f"Identified {len(threat_mapping['identified_threat_patterns'])} threat actor patterns:")
                    for pattern in threat_mapping["identified_threat_patterns"]:
                        print(f"  - {pattern['pattern']} (Confidence: {pattern['confidence']})")
                        print(f"    Associated actors: {', '.join(pattern['details']['associated_threat_actors'])}")
                        print(f"    Description: {pattern['details']['description']}")
                
                if threat_mapping["associated_threat_actors"]:
                    print(f"\n🎯 Potential Threat Actors: {', '.join(threat_mapping['associated_threat_actors'])}")
                
                if threat_mapping["recommended_actions"]:
                    print(f"\n📋 Recommended Actions:")
                    for action in threat_mapping["recommended_actions"]:
                        print(f"  - {action}")
        except Exception as e:
            print(f"⚠️  Threat actor mapping failed: {str(e)}")

    return analyzed_df


# ============ MAIN PIPELINE ============

def main():
    start_time = time.time()
    rules_data = load_rules(RULES_JSON_PATH)
    analyze_command = make_analyzer(rules_data)

    in_path = clean_path(INPUT_CSV_PATH)
    out_csv = clean_path(OUTPUT_CSV_PATH)
    out_xlsx = clean_path(OUTPUT_XLSX_PATH)

    print(f"Reading log file: {in_path}")
    # Use utf-8-sig to handle potential BOM from Excel-originated CSVs
    df = pd.read_csv(in_path, encoding='utf-8-sig')

    # Normalize column names and verify schema
    df.columns = df.columns.str.lower().map(sanitize_text)
    if "commandline" not in df.columns:
        print("ERROR: Could not find a 'Commandline' column in the input file.")
        print(f"Columns present: {list(df.columns)}")
        sys.exit(1)

    # Clean inputs to avoid Unicode artifacts and ensure consistent matching
    df["commandline"] = df["commandline"].astype(str).map(sanitize_text)

    print("Analyzing commands... This might take a moment for large files.")
    df["Analysis"] = df["commandline"].apply(analyze_command)
    df["Analysis"] = df["Analysis"].map(sanitize_text)

    # Perform behavioral analysis if enabled
    if ENABLE_BEHAVIORAL_ANALYSIS:
        df = perform_behavioral_analysis(df)

    # Write CSV with BOM so Excel recognizes UTF-8 correctly
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_csv, index=False, encoding='utf-8-sig')
    print(f"✅ CSV saved: {out_csv}")

    # Optionally write native Excel file (avoids CSV encoding quirks entirely)
    if WRITE_XLSX:
        try:
            # Requires openpyxl; if missing, we fall back gracefully
            df.to_excel(out_xlsx, index=False)
            print(f"✅ XLSX saved: {out_xlsx}")
        except ImportError:
            print("ℹ️  Skipped XLSX export (install 'openpyxl' to enable):")
            print("    python -m pip install openpyxl")

    # Print performance metrics
    print_metrics(analyze_command)
    
    # Summary
    print("\nQuick Summary of Findings:")
    # Ensure nice display even if terminal isn't fully UTF-8—data itself is clean
    print(df["Analysis"].value_counts())

    # Optionally show a few examples
    print("\nSample rows:")
    print(df.head(5).to_string(index=False))

    # Generate narrative summary
    print("\nNarrative Summary:")
    narrative_summary = generate_narrative_summary(df)
    print(narrative_summary)

    total_runtime = time.time() - start_time
    print(f"\nTotal runtime: {total_runtime:.4f}s")


# ============ ENTRYPOINT ============

if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as fnf:
            print(f"ERROR: {fnf}")
    except json.JSONDecodeError as je:
        print(f"ERROR: Failed to parse JSON rules. {je}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")