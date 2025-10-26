"""
Automated Threat Hunting System

Proactive threat hunting based on TTPs, IOCs, vulnerability patterns,
and threat intelligence to identify potential compromises.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

from .models import IoC, IoCType, ThreatActor, MitreAttackTechnique


class HuntingPriority(Enum):
    """Priority level for threat hunting."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HuntingStatus(Enum):
    """Status of threat hunting activity."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FINDINGS_DETECTED = "findings_detected"
    NO_FINDINGS = "no_findings"


@dataclass
class ThreatHunt:
    """Threat hunting activity."""
    
    # Hunt metadata
    hunt_id: str
    hunt_name: str
    description: str
    
    # Hunt parameters
    hunt_type: str  # "ioc", "ttp", "vulnerability", "anomaly"
    priority: HuntingPriority = HuntingPriority.MEDIUM
    status: HuntingStatus = HuntingStatus.PENDING
    
    # Hunt targets
    iocs: List[IoC] = field(default_factory=list)
    ttps: List[MitreAttackTechnique] = field(default_factory=list)
    threat_actors: List[ThreatActor] = field(default_factory=list)
    vulnerability_patterns: List[str] = field(default_factory=list)
    
    # Hunt scope
    target_systems: List[str] = field(default_factory=list)
    target_networks: List[str] = field(default_factory=list)
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    
    # Hunt results
    findings: List[Dict] = field(default_factory=list)
    indicators_found: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'hunt_id': self.hunt_id,
            'hunt_name': self.hunt_name,
            'description': self.description,
            'hunt_type': self.hunt_type,
            'priority': self.priority.value,
            'status': self.status.value,
            'iocs': [ioc.value for ioc in self.iocs],
            'ttps': [ttp.technique_id for ttp in self.ttps],
            'threat_actors': [actor.name for actor in self.threat_actors],
            'vulnerability_patterns': self.vulnerability_patterns,
            'target_systems': self.target_systems,
            'target_networks': self.target_networks,
            'time_range_start': self.time_range_start.isoformat() if self.time_range_start else None,
            'time_range_end': self.time_range_end.isoformat() if self.time_range_end else None,
            'findings': self.findings,
            'indicators_found': self.indicators_found,
            'confidence_score': self.confidence_score,
            'created_at': self.created_at.isoformat(),
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }


class ThreatHunter:
    """
    Automated threat hunting system.
    
    Proactively hunts for threats based on IOCs, TTPs, vulnerability patterns,
    and threat intelligence.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize threat hunter."""
        self.config = config or {}
        
        # Hunt queue
        self.active_hunts: Dict[str, ThreatHunt] = {}
        self.completed_hunts: List[ThreatHunt] = []
        
        # Hunt templates
        self.hunt_templates = self._initialize_hunt_templates()
        
        # Statistics
        self.total_hunts = 0
        self.successful_hunts = 0
        self.findings_detected = 0
    
    def _initialize_hunt_templates(self) -> Dict[str, Dict]:
        """Initialize predefined hunt templates."""
        return {
            'apt_activity': {
                'name': 'APT Activity Detection',
                'description': 'Hunt for APT-related IOCs and TTPs',
                'hunt_type': 'ttp',
                'priority': HuntingPriority.CRITICAL
            },
            'ransomware_indicators': {
                'name': 'Ransomware Indicators',
                'description': 'Hunt for ransomware-related IOCs and behaviors',
                'hunt_type': 'ioc',
                'priority': HuntingPriority.CRITICAL
            },
            'exploitation_attempts': {
                'name': 'Exploitation Attempts',
                'description': 'Hunt for vulnerability exploitation patterns',
                'hunt_type': 'vulnerability',
                'priority': HuntingPriority.HIGH
            },
            'lateral_movement': {
                'name': 'Lateral Movement Detection',
                'description': 'Hunt for lateral movement TTPs',
                'hunt_type': 'ttp',
                'priority': HuntingPriority.HIGH
            },
            'data_exfiltration': {
                'name': 'Data Exfiltration Detection',
                'description': 'Hunt for data exfiltration patterns',
                'hunt_type': 'ttp',
                'priority': HuntingPriority.HIGH
            },
            'command_and_control': {
                'name': 'C2 Communication Detection',
                'description': 'Hunt for command and control IOCs',
                'hunt_type': 'ioc',
                'priority': HuntingPriority.HIGH
            }
        }
    
    async def create_hunt(
        self,
        hunt_name: str,
        description: str,
        hunt_type: str,
        iocs: Optional[List[IoC]] = None,
        ttps: Optional[List[MitreAttackTechnique]] = None,
        threat_actors: Optional[List[ThreatActor]] = None,
        vulnerability_patterns: Optional[List[str]] = None,
        priority: HuntingPriority = HuntingPriority.MEDIUM,
        target_systems: Optional[List[str]] = None,
        target_networks: Optional[List[str]] = None,
        time_range_days: int = 30
    ) -> ThreatHunt:
        """
        Create a new threat hunt.
        
        Args:
            hunt_name: Name of the hunt
            description: Description of what to hunt for
            hunt_type: Type of hunt (ioc, ttp, vulnerability, anomaly)
            iocs: List of IOCs to hunt for
            ttps: List of TTPs to hunt for
            threat_actors: List of threat actors to hunt for
            vulnerability_patterns: List of vulnerability patterns
            priority: Hunt priority
            target_systems: Target systems to hunt in
            target_networks: Target networks to hunt in
            time_range_days: Time range to hunt (days back)
        
        Returns:
            ThreatHunt object
        """
        hunt_id = f"hunt-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{self.total_hunts}"
        
        hunt = ThreatHunt(
            hunt_id=hunt_id,
            hunt_name=hunt_name,
            description=description,
            hunt_type=hunt_type,
            priority=priority,
            iocs=iocs or [],
            ttps=ttps or [],
            threat_actors=threat_actors or [],
            vulnerability_patterns=vulnerability_patterns or [],
            target_systems=target_systems or [],
            target_networks=target_networks or [],
            time_range_start=datetime.utcnow() - timedelta(days=time_range_days),
            time_range_end=datetime.utcnow()
        )
        
        self.active_hunts[hunt_id] = hunt
        self.total_hunts += 1
        
        return hunt
    
    async def create_hunt_from_template(
        self,
        template_name: str,
        iocs: Optional[List[IoC]] = None,
        ttps: Optional[List[MitreAttackTechnique]] = None,
        threat_actors: Optional[List[ThreatActor]] = None,
        **kwargs
    ) -> ThreatHunt:
        """Create hunt from predefined template."""
        if template_name not in self.hunt_templates:
            raise ValueError(f"Unknown hunt template: {template_name}")
        
        template = self.hunt_templates[template_name]
        
        return await self.create_hunt(
            hunt_name=template['name'],
            description=template['description'],
            hunt_type=template['hunt_type'],
            priority=template['priority'],
            iocs=iocs,
            ttps=ttps,
            threat_actors=threat_actors,
            **kwargs
        )
    
    async def execute_hunt(self, hunt_id: str) -> ThreatHunt:
        """
        Execute a threat hunt.
        
        Args:
            hunt_id: Hunt identifier
        
        Returns:
            Updated ThreatHunt with results
        """
        if hunt_id not in self.active_hunts:
            raise ValueError(f"Hunt not found: {hunt_id}")
        
        hunt = self.active_hunts[hunt_id]
        hunt.status = HuntingStatus.IN_PROGRESS
        hunt.started_at = datetime.utcnow()
        
        # Execute hunt based on type
        if hunt.hunt_type == 'ioc':
            await self._hunt_iocs(hunt)
        elif hunt.hunt_type == 'ttp':
            await self._hunt_ttps(hunt)
        elif hunt.hunt_type == 'vulnerability':
            await self._hunt_vulnerabilities(hunt)
        elif hunt.hunt_type == 'anomaly':
            await self._hunt_anomalies(hunt)
        
        # Update status
        hunt.completed_at = datetime.utcnow()
        if hunt.findings:
            hunt.status = HuntingStatus.FINDINGS_DETECTED
            self.findings_detected += len(hunt.findings)
            self.successful_hunts += 1
        else:
            hunt.status = HuntingStatus.NO_FINDINGS
        
        # Move to completed
        self.completed_hunts.append(hunt)
        del self.active_hunts[hunt_id]
        
        return hunt
    
    async def _hunt_iocs(self, hunt: ThreatHunt):
        """Hunt for IOCs in environment."""
        findings = []
        
        for ioc in hunt.iocs:
            # Simulate IOC hunting (in production, this would query SIEM, logs, etc.)
            finding = await self._search_ioc(ioc, hunt)
            if finding:
                findings.append(finding)
                hunt.indicators_found.append(ioc.value)
        
        hunt.findings = findings
        hunt.confidence_score = self._calculate_confidence(findings)
    
    async def _hunt_ttps(self, hunt: ThreatHunt):
        """Hunt for TTPs in environment."""
        findings = []
        
        for ttp in hunt.ttps:
            # Simulate TTP hunting
            finding = await self._search_ttp(ttp, hunt)
            if finding:
                findings.append(finding)
                hunt.indicators_found.append(ttp.technique_id)
        
        hunt.findings = findings
        hunt.confidence_score = self._calculate_confidence(findings)
    
    async def _hunt_vulnerabilities(self, hunt: ThreatHunt):
        """Hunt for vulnerability exploitation patterns."""
        findings = []
        
        for pattern in hunt.vulnerability_patterns:
            # Simulate vulnerability pattern hunting
            finding = await self._search_vulnerability_pattern(pattern, hunt)
            if finding:
                findings.append(finding)
                hunt.indicators_found.append(pattern)
        
        hunt.findings = findings
        hunt.confidence_score = self._calculate_confidence(findings)
    
    async def _hunt_anomalies(self, hunt: ThreatHunt):
        """Hunt for anomalous behaviors."""
        # Simulate anomaly detection
        findings = []
        hunt.findings = findings
        hunt.confidence_score = self._calculate_confidence(findings)

    async def _search_ioc(self, ioc: IoC, hunt: ThreatHunt) -> Optional[Dict]:
        """Search for IOC in environment (simulated)."""
        # In production, this would query SIEM, EDR, logs, etc.
        # For now, simulate with random detection

        # Simulate search delay
        await asyncio.sleep(0.1)

        # Simulate finding (10% detection rate for demo)
        import random
        if random.random() < 0.1:
            return {
                'ioc': ioc.value,
                'ioc_type': ioc.ioc_type.value,
                'detected_at': datetime.utcnow().isoformat(),
                'source': 'SIEM',
                'confidence': 0.85,
                'details': f'IOC {ioc.value} detected in network traffic'
            }

        return None

    async def _search_ttp(self, ttp: MitreAttackTechnique, hunt: ThreatHunt) -> Optional[Dict]:
        """Search for TTP in environment (simulated)."""
        # In production, this would analyze behaviors, logs, etc.

        await asyncio.sleep(0.1)

        import random
        if random.random() < 0.08:
            return {
                'ttp': ttp.technique_id,
                'ttp_name': ttp.name,
                'detected_at': datetime.utcnow().isoformat(),
                'source': 'EDR',
                'confidence': 0.75,
                'details': f'TTP {ttp.technique_id} behavior detected'
            }

        return None

    async def _search_vulnerability_pattern(self, pattern: str, hunt: ThreatHunt) -> Optional[Dict]:
        """Search for vulnerability exploitation pattern (simulated)."""
        # In production, this would analyze WAF logs, IDS alerts, etc.

        await asyncio.sleep(0.1)

        import random
        if random.random() < 0.12:
            return {
                'pattern': pattern,
                'detected_at': datetime.utcnow().isoformat(),
                'source': 'WAF',
                'confidence': 0.80,
                'details': f'Exploitation pattern "{pattern}" detected in web traffic'
            }

        return None

    def _calculate_confidence(self, findings: List[Dict]) -> float:
        """Calculate overall confidence score for hunt."""
        if not findings:
            return 0.0

        # Average confidence of all findings
        confidences = [f.get('confidence', 0.5) for f in findings]
        avg_confidence = sum(confidences) / len(confidences)

        # Boost confidence with more findings
        finding_boost = min(len(findings) * 0.05, 0.2)

        return min(avg_confidence + finding_boost, 1.0)

    async def create_hunt_from_vulnerability(
        self,
        vulnerability_id: str,
        vulnerability_type: str,
        iocs: Optional[List[IoC]] = None,
        ttps: Optional[List[MitreAttackTechnique]] = None,
        threat_actors: Optional[List[ThreatActor]] = None
    ) -> ThreatHunt:
        """
        Create threat hunt based on vulnerability.

        Args:
            vulnerability_id: Vulnerability identifier
            vulnerability_type: Type of vulnerability
            iocs: Related IOCs
            ttps: Related TTPs
            threat_actors: Related threat actors

        Returns:
            ThreatHunt object
        """
        hunt_name = f"Hunt for {vulnerability_type} Exploitation"
        description = f"Hunt for exploitation of {vulnerability_id} ({vulnerability_type})"

        # Determine priority based on threat actors
        priority = HuntingPriority.MEDIUM
        if threat_actors:
            for actor in threat_actors:
                if 'apt' in actor.name.lower():
                    priority = HuntingPriority.CRITICAL
                    break

        # Create vulnerability patterns
        patterns = [vulnerability_type]
        if vulnerability_id:
            patterns.append(vulnerability_id)

        return await self.create_hunt(
            hunt_name=hunt_name,
            description=description,
            hunt_type='vulnerability',
            iocs=iocs,
            ttps=ttps,
            threat_actors=threat_actors,
            vulnerability_patterns=patterns,
            priority=priority,
            time_range_days=30
        )

    async def create_hunt_from_threat_actor(
        self,
        threat_actor: ThreatActor,
        iocs: Optional[List[IoC]] = None,
        ttps: Optional[List[MitreAttackTechnique]] = None
    ) -> ThreatHunt:
        """
        Create threat hunt based on threat actor.

        Args:
            threat_actor: Threat actor to hunt for
            iocs: Known IOCs for this actor
            ttps: Known TTPs for this actor

        Returns:
            ThreatHunt object
        """
        hunt_name = f"Hunt for {threat_actor.name} Activity"
        description = f"Hunt for indicators of {threat_actor.name} activity"

        # APT actors get critical priority
        priority = HuntingPriority.CRITICAL if 'apt' in threat_actor.name.lower() else HuntingPriority.HIGH

        return await self.create_hunt(
            hunt_name=hunt_name,
            description=description,
            hunt_type='ttp',
            iocs=iocs,
            ttps=ttps,
            threat_actors=[threat_actor],
            priority=priority,
            time_range_days=90  # Longer time range for APT hunting
        )

    def get_active_hunts(self) -> List[ThreatHunt]:
        """Get all active hunts."""
        return list(self.active_hunts.values())

    def get_completed_hunts(self, limit: int = 100) -> List[ThreatHunt]:
        """Get completed hunts."""
        return self.completed_hunts[-limit:]

    def get_hunt_by_id(self, hunt_id: str) -> Optional[ThreatHunt]:
        """Get hunt by ID."""
        if hunt_id in self.active_hunts:
            return self.active_hunts[hunt_id]

        for hunt in self.completed_hunts:
            if hunt.hunt_id == hunt_id:
                return hunt

        return None

    def get_statistics(self) -> Dict:
        """Get threat hunting statistics."""
        success_rate = 0.0
        if self.total_hunts > 0:
            success_rate = self.successful_hunts / self.total_hunts

        return {
            'total_hunts': self.total_hunts,
            'active_hunts': len(self.active_hunts),
            'completed_hunts': len(self.completed_hunts),
            'successful_hunts': self.successful_hunts,
            'success_rate': success_rate,
            'findings_detected': self.findings_detected,
            'avg_findings_per_hunt': self.findings_detected / max(self.total_hunts, 1)
        }

    async def batch_execute_hunts(self, hunt_ids: List[str]) -> List[ThreatHunt]:
        """
        Execute multiple hunts in parallel.

        Args:
            hunt_ids: List of hunt IDs to execute

        Returns:
            List of completed ThreatHunt objects
        """
        tasks = [self.execute_hunt(hunt_id) for hunt_id in hunt_ids]
        return await asyncio.gather(*tasks)
