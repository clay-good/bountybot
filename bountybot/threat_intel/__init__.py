"""
Threat Intelligence & Vulnerability Enrichment Module

Provides threat intelligence integration, CVE/NVD enrichment, exploit correlation,
MITRE ATT&CK mapping, IoC tracking, and vulnerability intelligence.
"""

from .models import (
    CVEData,
    ExploitData,
    ThreatFeed,
    ThreatIndicator,
    MitreAttackTechnique,
    VulnerabilityIntelligence,
    ThreatActor,
    IoC,
    IoCType,
    ThreatSeverity,
    ExploitMaturity,
    VulnerabilityStatus
)

from .cve_enricher import CVEEnricher
from .exploit_correlator import ExploitCorrelator
from .threat_feed_manager import ThreatFeedManager
from .mitre_mapper import MitreMapper
from .ioc_manager import IoC_Manager
from .vulnerability_intelligence import VulnerabilityIntelligenceEngine
from .threat_actor_profiler import ThreatActorProfiler
from .risk_contextualizer import RiskContextualizer

__all__ = [
    # Models
    'CVEData',
    'ExploitData',
    'ThreatFeed',
    'ThreatIndicator',
    'MitreAttackTechnique',
    'VulnerabilityIntelligence',
    'ThreatActor',
    'IoC',
    'IoCType',
    'ThreatSeverity',
    'ExploitMaturity',
    'VulnerabilityStatus',
    
    # Core Components
    'CVEEnricher',
    'ExploitCorrelator',
    'ThreatFeedManager',
    'MitreMapper',
    'IoC_Manager',
    'VulnerabilityIntelligenceEngine',
    'ThreatActorProfiler',
    'RiskContextualizer',
]

