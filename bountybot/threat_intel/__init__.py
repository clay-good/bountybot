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

# New v2.10.0 components
from .correlation_engine import (
    ThreatCorrelationEngine,
    ThreatCorrelation,
    CorrelationStrength
)
from .exploit_predictor import (
    ExploitPredictor,
    ExploitPrediction,
    ExploitLikelihood
)
from .threat_hunter import (
    ThreatHunter,
    ThreatHunt,
    HuntingPriority,
    HuntingStatus
)
from .enrichment_pipeline import (
    ThreatIntelligenceEnrichmentPipeline,
    EnrichedValidation
)

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

    # v2.10.0 - Advanced Security Intelligence
    'ThreatCorrelationEngine',
    'ThreatCorrelation',
    'CorrelationStrength',
    'ExploitPredictor',
    'ExploitPrediction',
    'ExploitLikelihood',
    'ThreatHunter',
    'ThreatHunt',
    'HuntingPriority',
    'HuntingStatus',
    'ThreatIntelligenceEnrichmentPipeline',
    'EnrichedValidation',
]

