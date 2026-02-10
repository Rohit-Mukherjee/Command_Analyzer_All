"""
Behavioral Analysis Module for Command Line Analyzer

This module provides behavioral analysis capabilities to detect
anomalous patterns and sequences in command line activities.
"""

import re
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import List, Dict, Tuple, Optional
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
import warnings
warnings.filterwarnings('ignore')


class BehavioralAnalyzer:
    """Class to perform behavioral analysis on command line data"""
    
    def __init__(self):
        self.command_patterns = defaultdict(list)
        self.user_behavior_profiles = {}
        self.anomaly_threshold = 2.0  # Standard deviations
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 3), max_features=1000)
        
    def extract_features(self, command: str) -> Dict[str, any]:
        """Extract behavioral features from a command line"""
        features = {
            'length': len(command),
            'num_args': len(command.split()),
            'has_path': bool(re.search(r'[A-Z]:\\|/', command)),
            'has_network': bool(re.search(r'http|ftp|\\\\|@\d+\.\d+\.\d+\.\d+', command)),
            'has_encoded': bool(re.search(r'-enc|encoded|base64', command, re.IGNORECASE)),
            'has_execution': bool(re.search(r'\.exe|\.dll|\.bat|\.ps1|\.vbs|\.js', command, re.IGNORECASE)),
            'has_privilege': bool(re.search(r'admin|root|sudo|system', command, re.IGNORECASE)),
            'has_crypto': bool(re.search(r'certutil|mimikatz|procdump|lsassy', command, re.IGNORECASE)),
            'has_download': bool(re.search(r'curl|wget|download|webclient', command, re.IGNORECASE)),
            'has_registry': bool(re.search(r'reg|registry|hkey', command, re.IGNORECASE)),
            'has_service': bool(re.search(r'sc|service|task', command, re.IGNORECASE)),
            'has_user': bool(re.search(r'user|account|password', command, re.IGNORECASE)),
            'has_file_ops': bool(re.search(r'copy|move|delete|del|rm|mkdir|touch', command, re.IGNORECASE)),
            'has_process': bool(re.search(r'tasklist|ps|kill|taskkill|process', command, re.IGNORECASE)),
            'complexity_score': self._calculate_complexity(command)
        }
        
        return features
    
    def _calculate_complexity(self, command: str) -> float:
        """Calculate a complexity score for the command"""
        score = 0
        # More complex if it has pipes, redirects, or multiple commands
        if '|' in command:
            score += 1
        if '>' in command or '>>' in command:
            score += 1
        if '&' in command or '&&' in command:
            score += 1
        if re.search(r'\$\(.*\)|`.*`', command):  # Command substitution
            score += 2
        if re.search(r'\{.*\}|\[.*\]', command):  # Braces or brackets
            score += 0.5
            
        # Normalize by command length
        return min(score, 5)  # Cap at 5 for normalization
    
    def detect_anomalies(self, df: pd.DataFrame, command_column: str = 'commandline') -> pd.DataFrame:
        """Detect anomalous command patterns in the dataset using multiple ML techniques"""
        df_copy = df.copy()

        # Extract features for all commands
        features_list = []
        for _, row in df_copy.iterrows():
            features = self.extract_features(str(row[command_column]))
            features_list.append(features)

        # Convert features to numerical representation for clustering
        feature_names = list(features_list[0].keys())
        feature_matrix = np.array([[f[name] for name in feature_names] for f in features_list])

        # Use multiple anomaly detection techniques for better accuracy
        anomaly_scores = np.zeros(len(df_copy))
        
        if len(df_copy) > 1:
            # Technique 1: Clustering-based anomaly detection
            n_clusters = min(len(df_copy), 3)  # At most 3 clusters for normal/abnormal distinction
            kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
            cluster_labels = kmeans.fit_predict(feature_matrix)

            # Calculate distances to cluster centers to identify outliers
            distances = kmeans.transform(feature_matrix)
            min_distances = np.min(distances, axis=1)
            
            # Normalize distances to 0-1 range
            if np.max(min_distances) > 0:
                normalized_distances = min_distances / np.max(min_distances)
            else:
                normalized_distances = min_distances
            
            # Technique 2: Isolation Forest for anomaly detection
            try:
                from sklearn.ensemble import IsolationForest
                iso_forest = IsolationForest(contamination=0.1, random_state=42)
                iso_anomaly_labels = iso_forest.fit_predict(feature_matrix)
                # Convert to anomaly scores (1 for anomaly, 0 for normal)
                iso_scores = (iso_anomaly_labels == -1).astype(int)
            except ImportError:
                # Fallback if isolation forest is not available
                iso_scores = np.zeros(len(df_copy))
            
            # Technique 3: Statistical outlier detection based on feature values
            feature_outliers = np.zeros(len(df_copy))
            for i in range(feature_matrix.shape[1]):
                if feature_matrix[:, i].std() > 0:  # Avoid division by zero
                    z_scores = np.abs((feature_matrix[:, i] - feature_matrix[:, i].mean()) / feature_matrix[:, i].std())
                    feature_outliers += (z_scores > 3).astype(int)  # Count features that are outliers
            
            # Combine all techniques with different weights
            # Clustering distance: 40%, Isolation Forest: 40%, Statistical: 20%
            combined_scores = (normalized_distances * 0.4 + 
                             iso_scores * 0.4 + 
                             (feature_outliers / feature_matrix.shape[1]) * 0.2)
            
            # Determine anomalies based on combined score
            mean_score = np.mean(combined_scores)
            std_score = np.std(combined_scores)
            
            if std_score > 0:
                anomaly_flags = combined_scores > (mean_score + self.anomaly_threshold * std_score)
            else:
                anomaly_flags = combined_scores > mean_score
        else:
            anomaly_flags = [False] * len(df_copy)
            combined_scores = np.zeros(len(df_copy))

        # Add behavioral analysis columns
        df_copy['is_anomaly'] = anomaly_flags
        df_copy['anomaly_score'] = combined_scores
        df_copy['behavioral_complexity'] = [f['complexity_score'] for f in features_list]
        df_copy['feature_vector'] = [str(f) for f in features_list]

        # Identify specific behavioral patterns
        df_copy['behavioral_flags'] = df_copy[command_column].apply(self._identify_behavioral_flags)

        return df_copy
    
    def _identify_behavioral_flags(self, command: str) -> List[str]:
        """Identify specific behavioral flags in a command"""
        flags = []
        cmd_lower = command.lower()
        
        if re.search(r'net\s+user\s+.*\s+/add', cmd_lower):
            flags.append('USER_CREATION')
        if re.search(r'net\s+localgroup\s+administrators', cmd_lower):
            flags.append('ADMIN_GROUP_MODIFICATION')
        if re.search(r'reg\s+add.*run|runonce', cmd_lower):
            flags.append('AUTOEXEC_REG_MOD')
        if re.search(r'powershell.*-enc', cmd_lower):
            flags.append('ENCODED_PAYLOAD')
        if re.search(r'procdump.*lsass', cmd_lower):
            flags.append('CREDENTIAL_DUMPING')
        if re.search(r'mimikatz', cmd_lower):
            flags.append('CREDENTIAL_TOOL_EXEC')
        if re.search(r'certutil.*urlcache|download', cmd_lower):
            flags.append('FILE_DOWNLOAD_UTIL')
        if re.search(r'bitsadmin|wget|curl', cmd_lower) and ('http' in cmd_lower or 'ftp' in cmd_lower):
            flags.append('NETWORK_FILE_TRANSFER')
        if re.search(r'schtasks.*create|at\s+', cmd_lower):
            flags.append('SCHEDULED_TASK_CREATION')
        if re.search(r'sc\s+create|sc\s+config', cmd_lower):
            flags.append('SERVICE_MANIPULATION')
        if re.search(r'rundll32|mshta|wmic', cmd_lower):
            flags.append('UNUSUAL_EXEC_METHOD')
        if re.search(r'\\temp\\|/tmp/', cmd_lower):
            flags.append('TEMP_DIR_EXECUTION')
        if re.search(r'powershell.*iex|invoke-expression', cmd_lower):
            flags.append('DYNAMIC_CODE_EXEC')
        if re.search(r'powershell.*bypass|executionpolicy', cmd_lower):
            flags.append('POLICY_BYPASS_ATTEMPT')
        if re.search(r'netsh.*firewall|advfirewall', cmd_lower):
            flags.append('FIREWALL_MANIPULATION')
        if re.search(r'vssadmin|wmic.*shadowcopy|wbadmin', cmd_lower):
            flags.append('BACKUP_MANIPULATION')
        if re.search(r'wevtutil.*clear|cleareventlog', cmd_lower):
            flags.append('LOG_MANIPULATION')
        
        return flags
    
    def sequence_analysis(self, df: pd.DataFrame, time_column: str = 'timestamp', 
                         command_column: str = 'commandline', user_column: str = 'user') -> Dict:
        """Analyze sequences of commands for suspicious patterns"""
        if time_column not in df.columns:
            # If no timestamp, create a sequential index
            df = df.copy()
            df[time_column] = range(len(df))
        
        # Group by user if user column exists
        if user_column in df.columns:
            grouped = df.groupby(user_column)
        else:
            # Create a single group if no user column
            df[user_column] = 'default_user'
            grouped = df.groupby(user_column)
        
        suspicious_sequences = []
        
        for user, group in grouped:
            # Sort by timestamp
            sorted_group = group.sort_values(by=time_column)
            
            # Look for suspicious command sequences
            commands = sorted_group[command_column].tolist()
            timestamps = sorted_group[time_column].tolist()
            
            # Check for suspicious sequences
            for i in range(len(commands) - 2):
                seq = commands[i:i+3]  # Look at sequences of 3 commands
                
                # Check for credential dumping sequence
                if self._is_credential_dumping_sequence(seq):
                    suspicious_sequences.append({
                        'user': user,
                        'sequence': seq,
                        'type': 'CREDENTIAL_DUMPING_SEQUENCE',
                        'start_time': timestamps[i] if i < len(timestamps) else None
                    })
                
                # Check for lateral movement prep sequence
                elif self._is_lateral_movement_sequence(seq):
                    suspicious_sequences.append({
                        'user': user,
                        'sequence': seq,
                        'type': 'LATERAL_MOVEMENT_PREPARATION',
                        'start_time': timestamps[i] if i < len(timestamps) else None
                    })
                
                # Check for persistence establishment sequence
                elif self._is_persistence_sequence(seq):
                    suspicious_sequences.append({
                        'user': user,
                        'sequence': seq,
                        'type': 'PERSISTENCE_ESTABLISHMENT',
                        'start_time': timestamps[i] if i < len(timestamps) else None
                    })
        
        return {
            'suspicious_sequences': suspicious_sequences,
            'total_sequences_found': len(suspicious_sequences)
        }
    
    def _is_credential_dumping_sequence(self, commands: List[str]) -> bool:
        """Check if a sequence of commands indicates credential dumping preparation"""
        cmd_str = ' '.join([c.lower() for c in commands])
        
        # Look for combinations that suggest credential dumping
        has_process_enum = any('tasklist' in c or 'ps ' in c for c in commands)
        has_memory_dump = any('procdump' in c or 'dump' in c for c in commands if 'lsass' in c.lower())
        has_credential_tool = any('mimikatz' in c or 'secretsdump' in c for c in commands)
        
        return (has_process_enum and has_memory_dump) or has_credential_tool
    
    def _is_lateral_movement_sequence(self, commands: List[str]) -> bool:
        """Check if a sequence suggests lateral movement preparation"""
        cmd_str = ' '.join([c.lower() for c in commands])
        
        # Look for network reconnaissance followed by execution
        has_net_enum = any('net ' in c and ('view' in c or 'use' in c or 'session' in c) for c in commands)
        has_remote_exec = any('psexec' in c or 'wmiexec' in c or 'smbexec' in c for c in commands)
        has_scheduled_task = any('schtasks' in c and 'create' in c for c in commands)
        
        return (has_net_enum and (has_remote_exec or has_scheduled_task))

    def _is_persistence_sequence(self, commands: List[str]) -> bool:
        """Check if a sequence suggests persistence mechanism setup"""
        cmd_str = ' '.join([c.lower() for c in commands])

        # Look for user creation followed by autorun setup
        has_user_create = any('net user' in c and '/add' in c for c in commands)
        has_auto_run = any('reg add' in c and ('run' in c or 'runonce' in c) for c in commands)
        has_service_create = any('sc create' in c or ('schtasks' in c and 'create' in c) for c in commands)

        return (has_user_create and (has_auto_run or has_service_create)) or has_service_create

    def identify_attack_chains(self, df: pd.DataFrame, time_column: str = 'timestamp',
                              command_column: str = 'commandline', user_column: str = 'user') -> List[Dict]:
        """Identify potential attack chains across multiple commands"""
        if time_column not in df.columns:
            # If no timestamp, create a sequential index
            df = df.copy()
            df[time_column] = pd.date_range(start='today', periods=len(df), freq='1min')

        # Group by user if user column exists
        if user_column in df.columns:
            grouped = df.groupby(user_column)
        else:
            # Create a single group if no user column
            df[user_column] = 'default_user'
            grouped = df.groupby(user_column)

        attack_chains = []

        for user, group in grouped:
            # Sort by timestamp
            sorted_group = group.sort_values(by=time_column)
            commands = sorted_group[command_column].tolist()
            timestamps = sorted_group[time_column].tolist()
            analyses = sorted_group.get('Analysis', ['Unknown'] * len(commands)).tolist()
            
            # Look for attack chains of various lengths
            for window_size in [2, 3, 4]:  # Look for chains of 2-4 commands
                for i in range(len(commands) - window_size + 1):
                    chain_commands = commands[i:i+window_size]
                    chain_timestamps = timestamps[i:i+window_size]
                    
                    # Calculate duration of the chain
                    duration = chain_timestamps[-1] - chain_timestamps[0] if len(chain_timestamps) > 1 else pd.Timedelta(seconds=0)
                    
                    # Identify the type of attack chain
                    chain_type = self._identify_chain_type(chain_commands)
                    
                    if chain_type != 'NORMAL':
                        # Assess risk level based on chain type
                        risk_level = self._assess_chain_risk(chain_type, chain_commands)
                        
                        attack_chains.append({
                            'user': user,
                            'steps': chain_commands,
                            'analyses': analyses[i:i+window_size],
                            'start_time': chain_timestamps[0],
                            'end_time': chain_timestamps[-1],
                            'duration': str(duration),
                            'chain_type': chain_type,
                            'risk_level': risk_level
                        })

        # Sort chains by risk level and return
        attack_chains.sort(key=lambda x: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(x['risk_level']), reverse=True)
        return attack_chains

    def _identify_chain_type(self, commands: List[str]) -> str:
        """Identify the type of attack chain based on command patterns"""
        cmd_str = ' '.join([c.lower() for c in commands])
        
        # Reconnaissance chain: system info gathering followed by network discovery
        recon_indicators = ['systeminfo', 'whoami', 'hostname', 'ipconfig', 'netstat', 'arp', 'route']
        recon_count = sum(1 for cmd in commands for indicator in recon_indicators if indicator in cmd.lower())
        
        # Lateral movement: network discovery followed by remote execution
        lateral_indicators = ['net view', 'net use', 'psexec', 'wmiexec', 'smbexec', 'winexe']
        lateral_count = sum(1 for cmd in commands for indicator in lateral_indicators if indicator in cmd.lower())
        
        # Persistence: user creation followed by autorun/service setup
        persistence_indicators = ['net user', 'reg add', 'sc create', 'schtasks', 'crontab']
        persistence_count = sum(1 for cmd in commands for indicator in persistence_indicators if indicator in cmd.lower())
        
        # Credential access: process enumeration followed by credential dumping
        cred_indicators = ['tasklist', 'ps', 'procdump', 'mimikatz', 'secretsdump']
        cred_count = sum(1 for cmd in commands for indicator in cred_indicators if indicator in cmd.lower())
        
        # Defense evasion: service manipulation followed by log clearing
        evasion_indicators = ['sc stop', 'net stop', 'wevtutil', 'del', 'erase']
        evasion_count = sum(1 for cmd in commands for indicator in evasion_indicators if indicator in cmd.lower())
        
        # Determine chain type based on highest indicator count
        max_count = max(recon_count, lateral_count, persistence_count, cred_count, evasion_count)
        
        if max_count == 0:
            return 'NORMAL'
        elif recon_count == max_count:
            return 'RECONNAISSANCE'
        elif lateral_count == max_count:
            return 'LATERAL_MOVEMENT'
        elif persistence_count == max_count:
            return 'PERSISTENCE'
        elif cred_count == max_count:
            return 'CREDENTIAL_ACCESS'
        elif evasion_count == max_count:
            return 'DEFENSE_EVASION'
        else:
            return 'MIXED'

    def _assess_chain_risk(self, chain_type: str, commands: List[str]) -> str:
        """Assess the risk level of an attack chain"""
        # Base risk on chain type
        risk_map = {
            'NORMAL': 'LOW',
            'RECONNAISSANCE': 'MEDIUM',
            'LATERAL_MOVEMENT': 'HIGH',
            'PERSISTENCE': 'HIGH',
            'CREDENTIAL_ACCESS': 'CRITICAL',
            'DEFENSE_EVASION': 'HIGH',
            'MIXED': 'HIGH'
        }
        
        base_risk = risk_map.get(chain_type, 'MEDIUM')
        
        # Increase risk if specific dangerous commands are present
        dangerous_commands = [
            'mimikatz', 'procdump.*lsass', 'wevtutil.*clear', 'vssadmin.*delete',
            'bcdedit.*recoveryenabled', 'wbadmin.*delete', 'diskshadow'
        ]
        
        for cmd in commands:
            for danger_cmd in dangerous_commands:
                if re.search(danger_cmd, cmd, re.IGNORECASE):
                    # Upgrade risk level
                    if base_risk == 'MEDIUM':
                        return 'HIGH'
                    elif base_risk == 'HIGH':
                        return 'CRITICAL'
                    elif base_risk == 'LOW':
                        return 'MEDIUM'
        
        return base_risk
    
    def generate_behavioral_report(self, df: pd.DataFrame) -> str:
        """Generate a comprehensive behavioral analysis report"""
        report = []
        report.append("ADVANCED BEHAVIORAL ANALYSIS REPORT")
        report.append("=" * 60)

        # Anomaly statistics
        if 'is_anomaly' in df.columns:
            anomaly_count = df['is_anomaly'].sum()
            total_count = len(df)
            anomaly_percentage = (anomaly_count / total_count) * 100 if total_count > 0 else 0

            report.append(f"Total Commands Analyzed: {total_count}")
            report.append(f"Anomalous Commands: {anomaly_count} ({anomaly_percentage:.2f}%)")
            
            # Add anomaly score statistics if available
            if 'anomaly_score' in df.columns:
                avg_anomaly_score = df['anomaly_score'].mean()
                max_anomaly_score = df['anomaly_score'].max()
                report.append(f"Average Anomaly Score: {avg_anomaly_score:.3f}")
                report.append(f"Maximum Anomaly Score: {max_anomaly_score:.3f}")
            report.append("")

        # Behavioral flag statistics
        if 'behavioral_flags' in df.columns:
            all_flags = [flag for flags in df['behavioral_flags'] for flag in flags]
            flag_counts = Counter(all_flags)

            report.append("Behavioral Flags Detected:")
            for flag, count in flag_counts.most_common():
                report.append(f"  {flag}: {count}")
            report.append("")

        # Complexity statistics
        if 'behavioral_complexity' in df.columns:
            avg_complexity = df['behavioral_complexity'].mean()
            max_complexity = df['behavioral_complexity'].max()

            report.append(f"Average Behavioral Complexity: {avg_complexity:.2f}")
            report.append(f"Maximum Behavioral Complexity: {max_complexity:.2f}")
            report.append("")

        # Add suspicious sequences if available
        try:
            seq_analysis = self.sequence_analysis(df)
            report.append(f"Suspicious Sequences Found: {seq_analysis['total_sequences_found']}")
            for seq in seq_analysis['suspicious_sequences'][:5]:  # Show first 5
                report.append(f"  Type: {seq['type']}")
                report.append(f"  User: {seq['user']}")
                report.append(f"  Sequence: {' -> '.join(seq['sequence'])}")
                report.append("")
        except Exception as e:
            report.append(f"Sequence analysis error: {str(e)}")
            
        # Add attack chain analysis
        try:
            attack_chains = self.identify_attack_chains(df)
            report.append(f"\nPotential Attack Chains Identified: {len(attack_chains)}")
            for chain in attack_chains[:3]:  # Show first 3 chains
                report.append(f"  Chain: {' -> '.join(chain['steps'])}")
                report.append(f"  Duration: {chain['duration']}")
                report.append(f"  Risk Level: {chain['risk_level']}")
                report.append("")
        except Exception as e:
            report.append(f"Attack chain analysis error: {str(e)}")

        # Add risk assessment
        risk_level = self._assess_risk_level(df, anomaly_count, anomaly_percentage, flag_counts)
        report.append(f"Overall Risk Level: {risk_level}")
        
        # Add recommendations
        report.append("\nRECOMMENDATIONS:")
        if anomaly_percentage > 20:
            report.append("- HIGH PRIORITY: Investigate all anomalous commands immediately")
            report.append("- Review user access controls and permissions")
        elif anomaly_percentage > 5:
            report.append("- MEDIUM PRIORITY: Investigate anomalous commands")
            report.append("- Monitor for similar patterns in the future")
        else:
            report.append("- LOW PRIORITY: Normal activity levels detected")
            report.append("- Continue routine monitoring")
            
        if 'CREDENTIAL_DUMPING' in flag_counts or 'CREDENTIAL_TOOL_EXEC' in flag_counts:
            report.append("- CRITICAL: Credential dumping activity detected - investigate immediately")
        if 'BACKUP_MANIPULATION' in flag_counts:
            report.append("- CRITICAL: Backup manipulation detected - potential ransomware preparation")

        return "\n".join(report)

    def _assess_risk_level(self, df: pd.DataFrame, anomaly_count: int, anomaly_percentage: float, flag_counts: Counter) -> str:
        """Assess the overall risk level based on analysis results"""
        risk_score = 0
        
        # Anomaly percentage contributes to risk
        if anomaly_percentage > 20:
            risk_score += 3
        elif anomaly_percentage > 5:
            risk_score += 2
        elif anomaly_percentage > 0:
            risk_score += 1
            
        # Critical behavioral flags contribute heavily to risk
        critical_flags = ['CREDENTIAL_DUMPING', 'CREDENTIAL_TOOL_EXEC', 'BACKUP_MANIPULATION', 
                         'LOG_MANIPULATION', 'SERVICE_MANIPULATION']
        for flag in critical_flags:
            if flag in flag_counts:
                risk_score += flag_counts[flag] * 2  # Weight critical flags more heavily
                
        # High complexity commands may indicate sophisticated attacks
        if 'behavioral_complexity' in df.columns:
            high_complexity_count = sum(1 for x in df['behavioral_complexity'] if x > 3.0)
            if high_complexity_count > 0:
                risk_score += min(high_complexity_count, 5)  # Cap at 5 points
                
        # Determine risk level based on score
        if risk_score >= 8:
            return "CRITICAL"
        elif risk_score >= 5:
            return "HIGH"
        elif risk_score >= 3:
            return "MEDIUM"
        else:
            return "LOW"


# Example usage and testing
if __name__ == "__main__":
    # Create sample data for testing
    sample_data = {
        'commandline': [
            'net user hacker password123 /add',
            'net localgroup administrators hacker /add',
            'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d "C:\\temp\\backdoor.exe" /f',
            'powershell -enc JAB[encoded payload]',
            'procdump.exe -ma lsass.exe C:\\temp\\dump.dmp',
            'normal command without suspicious elements',
            'curl http://example.com/file.exe -o C:\\temp\\file.exe',
            'schtasks /create /tn "Update" /tr "C:\\temp\\malware.exe" /sc ONSTART'
        ]
    }
    
    df = pd.DataFrame(sample_data)
    
    # Initialize behavioral analyzer
    ba = BehavioralAnalyzer()
    
    # Perform behavioral analysis
    analyzed_df = ba.detect_anomalies(df)
    
    # Print results
    print("Command Analysis Results:")
    for idx, row in analyzed_df.iterrows():
        print(f"Command: {row['commandline']}")
        print(f"  Is Anomaly: {row['is_anomaly']}")
        print(f"  Complexity: {row['behavioral_complexity']:.2f}")
        print(f"  Flags: {row['behavioral_flags']}")
        print()
    
    # Generate behavioral report
    report = ba.generate_behavioral_report(analyzed_df)
    print(report)