"""
Threat Intelligence Data Models
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional


class ThreatSeverity(str, Enum):
    """Threat severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExploitMaturity(str, Enum):
    """Exploit maturity levels."""
    UNPROVEN = "unproven"
    PROOF_OF_CONCEPT = "proof_of_concept"
    FUNCTIONAL = "functional"
    HIGH = "high"
    NOT_DEFINED = "not_defined"


class VulnerabilityStatus(str, Enum):
    """Vulnerability lifecycle status."""
    DISCOVERED = "discovered"
    DISCLOSED = "disclosed"
    PATCH_AVAILABLE = "patch_available"
    PATCH_DEPLOYED = "patch_deployed"
    ACTIVELY_EXPLOITED = "actively_exploited"
    MITIGATED = "mitigated"


class IoCType(str, Enum):
    """Indicator of Compromise types."""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"


@dataclass
class CVEData:
    """CVE/NVD vulnerability data."""
    cve_id: str
    description: str
    published_date: datetime
    last_modified_date: datetime
    
    # CVSS Scoring
    cvss_v3_score: Optional[float] = None
    cvss_v3_vector: Optional[str] = None
    cvss_v2_score: Optional[float] = None
    cvss_v2_vector: Optional[str] = None
    
    # Vulnerability Details
    cwe_ids: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    # Patch Information
    patch_available: bool = False
    patch_urls: List[str] = field(default_factory=list)
    
    # Metadata
    source: str = "NVD"
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExploitData:
    """Exploit database information."""
    exploit_id: str
    title: str
    description: str
    
    # Exploit Details
    cve_ids: List[str] = field(default_factory=list)
    exploit_type: str = ""  # remote, local, webapps, dos
    platform: str = ""  # windows, linux, multiple, etc.
    
    # Maturity Assessment
    maturity: ExploitMaturity = ExploitMaturity.NOT_DEFINED
    verified: bool = False
    
    # Source Information
    source: str = "ExploitDB"  # ExploitDB, Metasploit, GitHub, etc.
    source_url: str = ""
    published_date: Optional[datetime] = None
    
    # Code Availability
    code_available: bool = False
    code_url: Optional[str] = None
    
    # Metadata
    author: str = ""
    tags: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatIndicator:
    """Threat intelligence indicator."""
    indicator_id: str
    indicator_type: IoCType
    value: str
    
    # Threat Context
    threat_types: List[str] = field(default_factory=list)  # malware, phishing, c2, etc.
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    confidence: float = 0.0  # 0.0 to 1.0
    
    # Attribution
    threat_actors: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)
    
    # Temporal Information
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    
    # Context
    description: str = ""
    tags: List[str] = field(default_factory=list)
    
    # Source
    sources: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatFeed:
    """Threat intelligence feed configuration."""
    feed_id: str
    name: str
    feed_type: str  # STIX, TAXII, JSON, CSV, custom
    url: str
    
    # Configuration
    enabled: bool = True
    update_frequency: int = 3600  # seconds
    priority: int = 5  # 1-10, higher is more important
    
    # Authentication
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    
    # Filtering
    indicator_types: List[IoCType] = field(default_factory=list)
    min_confidence: float = 0.5
    
    # Metadata
    last_update: Optional[datetime] = None
    total_indicators: int = 0
    description: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class MitreAttackTechnique:
    """MITRE ATT&CK technique mapping."""
    technique_id: str  # T1234
    name: str
    description: str
    
    # Hierarchy
    tactic: str  # Initial Access, Execution, etc.
    sub_technique_of: Optional[str] = None
    
    # Detection
    detection_methods: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    
    # Mitigation
    mitigations: List[str] = field(default_factory=list)
    
    # Context
    platforms: List[str] = field(default_factory=list)
    permissions_required: List[str] = field(default_factory=list)
    
    # References
    references: List[str] = field(default_factory=list)
    
    # Metadata
    version: str = "1.0"
    created: Optional[datetime] = None
    modified: Optional[datetime] = None


@dataclass
class ThreatActor:
    """Threat actor profile."""
    actor_id: str
    name: str
    aliases: List[str] = field(default_factory=list)
    
    # Classification
    actor_type: str = ""  # APT, cybercrime, hacktivist, nation-state
    sophistication: str = ""  # novice, intermediate, advanced, expert
    
    # TTPs
    techniques: List[str] = field(default_factory=list)  # MITRE ATT&CK IDs
    tools: List[str] = field(default_factory=list)
    malware: List[str] = field(default_factory=list)
    
    # Targeting
    target_industries: List[str] = field(default_factory=list)
    target_countries: List[str] = field(default_factory=list)
    
    # Attribution
    attributed_campaigns: List[str] = field(default_factory=list)
    confidence: float = 0.0  # 0.0 to 1.0
    
    # Temporal
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    
    # Context
    description: str = ""
    motivation: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class IoC:
    """Indicator of Compromise."""
    ioc_id: str
    ioc_type: IoCType
    value: str
    
    # Context
    description: str = ""
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    confidence: float = 0.0
    
    # Attribution
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    malware_family: Optional[str] = None
    
    # Reputation
    reputation_score: float = 0.0  # -1.0 (malicious) to 1.0 (benign)
    
    # Temporal
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    expiration: Optional[datetime] = None
    
    # Source
    sources: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityIntelligence:
    """Vulnerability intelligence and trending data."""
    vuln_id: str  # CVE ID or internal ID
    
    # Status
    status: VulnerabilityStatus = VulnerabilityStatus.DISCOVERED
    
    # Exploitation
    exploit_available: bool = False
    exploit_public: bool = False
    actively_exploited: bool = False
    exploit_in_wild: bool = False
    
    # Trending
    trending_score: float = 0.0  # 0.0 to 1.0
    social_media_mentions: int = 0
    dark_web_mentions: int = 0
    
    # Timeline
    discovery_date: Optional[datetime] = None
    disclosure_date: Optional[datetime] = None
    patch_date: Optional[datetime] = None
    first_exploit_date: Optional[datetime] = None
    
    # Risk Assessment
    risk_score: float = 0.0  # 0.0 to 10.0
    exploitability_score: float = 0.0  # 0.0 to 1.0
    impact_score: float = 0.0  # 0.0 to 1.0
    
    # Context
    affected_systems: int = 0
    related_cves: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    
    # Metadata
    last_updated: Optional[datetime] = None
    sources: List[str] = field(default_factory=list)

