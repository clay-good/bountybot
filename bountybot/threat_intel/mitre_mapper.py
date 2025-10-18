"""
MITRE ATT&CK Mapper

Maps vulnerabilities and attacks to MITRE ATT&CK framework.
"""

import secrets
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
import json

from .models import MitreAttackTechnique


class MitreMapper:
    """MITRE ATT&CK framework mapper."""
    
    # MITRE ATT&CK Tactics
    TACTICS = [
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact"
    ]
    
    def __init__(self, data_dir: str = "./mitre_data"):
        """
        Initialize MITRE mapper.
        
        Args:
            data_dir: Directory for MITRE ATT&CK data
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.techniques: Dict[str, MitreAttackTechnique] = {}
        
        # Load techniques
        self._load_techniques()
    
    def map_vulnerability_to_techniques(self, cve_id: str, description: str) -> List[MitreAttackTechnique]:
        """
        Map vulnerability to MITRE ATT&CK techniques.
        
        Args:
            cve_id: CVE identifier
            description: Vulnerability description
            
        Returns:
            List of relevant MITRE ATT&CK techniques
        """
        techniques = []
        
        # Keyword-based mapping (simplified for demo)
        keywords_map = {
            'T1190': ['remote code execution', 'rce', 'exploit public-facing'],
            'T1059': ['command injection', 'code injection', 'script execution'],
            'T1055': ['process injection', 'dll injection'],
            'T1078': ['valid accounts', 'credential', 'authentication bypass'],
            'T1110': ['brute force', 'password spray'],
            'T1003': ['credential dumping', 'password hash'],
            'T1071': ['application layer protocol', 'http', 'https'],
            'T1566': ['phishing', 'spearphishing'],
            'T1068': ['privilege escalation', 'elevation of privilege'],
            'T1211': ['exploitation for defense evasion']
        }
        
        description_lower = description.lower()
        
        for technique_id, keywords in keywords_map.items():
            if any(keyword in description_lower for keyword in keywords):
                technique = self.get_technique(technique_id)
                if technique:
                    techniques.append(technique)
        
        return techniques
    
    def get_technique(self, technique_id: str) -> Optional[MitreAttackTechnique]:
        """
        Get MITRE ATT&CK technique by ID.
        
        Args:
            technique_id: Technique ID (e.g., T1190)
            
        Returns:
            MitreAttackTechnique or None
        """
        return self.techniques.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: str) -> List[MitreAttackTechnique]:
        """
        Get all techniques for a tactic.
        
        Args:
            tactic: Tactic name
            
        Returns:
            List of techniques
        """
        return [t for t in self.techniques.values() if t.tactic == tactic]
    
    def get_kill_chain_analysis(self, technique_ids: List[str]) -> Dict[str, Any]:
        """
        Analyze attack kill chain from techniques.
        
        Args:
            technique_ids: List of technique IDs
            
        Returns:
            Kill chain analysis
        """
        techniques = [self.get_technique(tid) for tid in technique_ids if self.get_technique(tid)]
        
        # Group by tactic
        tactics_used = {}
        for technique in techniques:
            tactic = technique.tactic
            if tactic not in tactics_used:
                tactics_used[tactic] = []
            tactics_used[tactic].append(technique.technique_id)
        
        # Determine kill chain stage
        tactic_order = {tactic: i for i, tactic in enumerate(self.TACTICS)}
        stages = sorted(tactics_used.keys(), key=lambda t: tactic_order.get(t, 999))
        
        return {
            'techniques_count': len(techniques),
            'tactics_covered': len(tactics_used),
            'kill_chain_stages': stages,
            'tactics_used': tactics_used,
            'coverage_percentage': (len(tactics_used) / len(self.TACTICS)) * 100
        }
    
    def _load_techniques(self):
        """Load MITRE ATT&CK techniques."""
        # Sample techniques for demo
        # In production, load from MITRE ATT&CK STIX data
        
        sample_techniques = [
            MitreAttackTechnique(
                technique_id="T1190",
                name="Exploit Public-Facing Application",
                description="Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.",
                tactic="Initial Access",
                detection_methods=[
                    "Monitor application logs for abnormal behavior",
                    "Use intrusion detection systems",
                    "Monitor for suspicious network traffic"
                ],
                data_sources=["Application logs", "Network traffic", "Packet capture"],
                mitigations=[
                    "Application Isolation and Sandboxing",
                    "Exploit Protection",
                    "Network Segmentation",
                    "Privileged Account Management",
                    "Update Software"
                ],
                platforms=["Linux", "Windows", "macOS", "Network"],
                permissions_required=["User"],
                references=["https://attack.mitre.org/techniques/T1190/"]
            ),
            MitreAttackTechnique(
                technique_id="T1059",
                name="Command and Scripting Interpreter",
                description="Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                tactic="Execution",
                detection_methods=[
                    "Monitor executed commands and arguments",
                    "Monitor for suspicious process execution",
                    "Analyze command-line parameters"
                ],
                data_sources=["Process monitoring", "Command execution logs"],
                mitigations=[
                    "Code Signing",
                    "Disable or Remove Feature or Program",
                    "Execution Prevention",
                    "Restrict File and Directory Permissions"
                ],
                platforms=["Linux", "Windows", "macOS"],
                permissions_required=["User"],
                references=["https://attack.mitre.org/techniques/T1059/"]
            ),
            MitreAttackTechnique(
                technique_id="T1078",
                name="Valid Accounts",
                description="Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
                tactic="Initial Access",
                detection_methods=[
                    "Monitor for suspicious account behavior",
                    "Correlate authentication logs",
                    "Detect anomalous login patterns"
                ],
                data_sources=["Authentication logs", "Access logs"],
                mitigations=[
                    "Account Use Policies",
                    "Multi-factor Authentication",
                    "Password Policies",
                    "Privileged Account Management"
                ],
                platforms=["Linux", "Windows", "macOS", "Cloud"],
                permissions_required=["User", "Administrator"],
                references=["https://attack.mitre.org/techniques/T1078/"]
            ),
            MitreAttackTechnique(
                technique_id="T1068",
                name="Exploitation for Privilege Escalation",
                description="Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.",
                tactic="Privilege Escalation",
                detection_methods=[
                    "Monitor for unusual process execution",
                    "Detect privilege escalation attempts",
                    "Monitor system calls"
                ],
                data_sources=["Process monitoring", "System calls"],
                mitigations=[
                    "Application Isolation and Sandboxing",
                    "Exploit Protection",
                    "Threat Intelligence Program",
                    "Update Software"
                ],
                platforms=["Linux", "Windows", "macOS"],
                permissions_required=["User"],
                references=["https://attack.mitre.org/techniques/T1068/"]
            ),
            MitreAttackTechnique(
                technique_id="T1071",
                name="Application Layer Protocol",
                description="Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
                tactic="Command and Control",
                detection_methods=[
                    "Monitor network traffic",
                    "Analyze protocol usage",
                    "Detect anomalous connections"
                ],
                data_sources=["Network traffic", "Packet capture", "Netflow"],
                mitigations=[
                    "Network Intrusion Prevention",
                    "Network Segmentation"
                ],
                platforms=["Linux", "Windows", "macOS", "Network"],
                permissions_required=["User"],
                references=["https://attack.mitre.org/techniques/T1071/"]
            )
        ]
        
        for technique in sample_techniques:
            self.techniques[technique.technique_id] = technique

