"""
Real-Time Threat Correlation Engine

Correlates vulnerabilities with CVEs, exploits, threat actors, IOCs, and MITRE ATT&CK
techniques in real-time to provide comprehensive threat intelligence context.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .models import (
    CVEData, ExploitData, ThreatActor, IoC, MitreAttackTechnique,
    ExploitMaturity, ThreatSeverity
)


class CorrelationStrength(Enum):
    """Strength of correlation between entities."""
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    CRITICAL = "critical"


@dataclass
class ThreatCorrelation:
    """Correlation between vulnerability and threat intelligence."""
    
    # Core vulnerability info
    vulnerability_id: str
    vulnerability_type: str
    
    # CVE correlations
    cves: List[CVEData] = field(default_factory=list)
    
    # Exploit correlations
    exploits: List[ExploitData] = field(default_factory=list)
    exploit_maturity: Optional[ExploitMaturity] = None
    
    # Threat actor correlations
    threat_actors: List[ThreatActor] = field(default_factory=list)
    
    # IOC correlations
    iocs: List[IoC] = field(default_factory=list)
    
    # MITRE ATT&CK correlations
    mitre_techniques: List[MitreAttackTechnique] = field(default_factory=list)
    
    # Correlation metadata
    correlation_strength: CorrelationStrength = CorrelationStrength.WEAK
    correlation_score: float = 0.0
    confidence: float = 0.0
    
    # Threat context
    threat_severity: ThreatSeverity = ThreatSeverity.LOW
    active_campaigns: List[str] = field(default_factory=list)
    targeted_industries: List[str] = field(default_factory=list)
    targeted_regions: List[str] = field(default_factory=list)
    
    # Temporal context
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    trending: bool = False
    
    # Risk indicators
    exploit_in_wild: bool = False
    ransomware_associated: bool = False
    apt_associated: bool = False
    weaponized: bool = False
    
    # Recommendations
    priority_score: float = 0.0
    recommended_actions: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'vulnerability_id': self.vulnerability_id,
            'vulnerability_type': self.vulnerability_type,
            'cves': [cve.cve_id for cve in self.cves],
            'exploits': [exp.exploit_id for exp in self.exploits],
            'exploit_maturity': self.exploit_maturity.value if self.exploit_maturity else None,
            'threat_actors': [actor.name for actor in self.threat_actors],
            'iocs': [ioc.value for ioc in self.iocs],
            'mitre_techniques': [tech.technique_id for tech in self.mitre_techniques],
            'correlation_strength': self.correlation_strength.value,
            'correlation_score': self.correlation_score,
            'confidence': self.confidence,
            'threat_severity': self.threat_severity.value,
            'active_campaigns': self.active_campaigns,
            'targeted_industries': self.targeted_industries,
            'targeted_regions': self.targeted_regions,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'trending': self.trending,
            'exploit_in_wild': self.exploit_in_wild,
            'ransomware_associated': self.ransomware_associated,
            'apt_associated': self.apt_associated,
            'weaponized': self.weaponized,
            'priority_score': self.priority_score,
            'recommended_actions': self.recommended_actions
        }


class ThreatCorrelationEngine:
    """
    Real-time threat correlation engine.
    
    Correlates vulnerabilities with threat intelligence from multiple sources
    to provide comprehensive security context.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize correlation engine."""
        self.config = config or {}
        
        # Correlation thresholds
        self.weak_threshold = self.config.get('weak_threshold', 0.3)
        self.moderate_threshold = self.config.get('moderate_threshold', 0.5)
        self.strong_threshold = self.config.get('strong_threshold', 0.7)
        self.critical_threshold = self.config.get('critical_threshold', 0.9)
        
        # Temporal windows
        self.trending_window_days = self.config.get('trending_window_days', 7)
        self.recent_activity_days = self.config.get('recent_activity_days', 30)
        
        # Correlation cache
        self.correlation_cache: Dict[str, ThreatCorrelation] = {}
        self.cache_ttl_seconds = self.config.get('cache_ttl_seconds', 3600)
        
        # Statistics
        self.total_correlations = 0
        self.cache_hits = 0
        self.cache_misses = 0
    
    async def correlate(
        self,
        vulnerability_id: str,
        vulnerability_type: str,
        cves: Optional[List[CVEData]] = None,
        exploits: Optional[List[ExploitData]] = None,
        threat_actors: Optional[List[ThreatActor]] = None,
        iocs: Optional[List[IoC]] = None,
        mitre_techniques: Optional[List[MitreAttackTechnique]] = None,
        force_refresh: bool = False
    ) -> ThreatCorrelation:
        """
        Correlate vulnerability with threat intelligence.
        
        Args:
            vulnerability_id: Unique vulnerability identifier
            vulnerability_type: Type of vulnerability (e.g., "SQL Injection")
            cves: Related CVE data
            exploits: Related exploit data
            threat_actors: Related threat actors
            iocs: Related indicators of compromise
            mitre_techniques: Related MITRE ATT&CK techniques
            force_refresh: Force refresh of cached correlation
        
        Returns:
            ThreatCorrelation with comprehensive threat context
        """
        # Check cache
        cache_key = f"{vulnerability_id}:{vulnerability_type}"
        if not force_refresh and cache_key in self.correlation_cache:
            self.cache_hits += 1
            return self.correlation_cache[cache_key]
        
        self.cache_misses += 1
        self.total_correlations += 1
        
        # Initialize correlation
        correlation = ThreatCorrelation(
            vulnerability_id=vulnerability_id,
            vulnerability_type=vulnerability_type,
            cves=cves or [],
            exploits=exploits or [],
            threat_actors=threat_actors or [],
            iocs=iocs or [],
            mitre_techniques=mitre_techniques or []
        )
        
        # Perform correlation analysis
        await self._analyze_exploit_maturity(correlation)
        await self._analyze_threat_actors(correlation)
        await self._analyze_temporal_context(correlation)
        await self._analyze_risk_indicators(correlation)
        await self._calculate_correlation_strength(correlation)
        await self._generate_recommendations(correlation)
        
        # Cache result
        self.correlation_cache[cache_key] = correlation
        
        return correlation
    
    async def _analyze_exploit_maturity(self, correlation: ThreatCorrelation):
        """Analyze exploit maturity level."""
        if not correlation.exploits:
            correlation.exploit_maturity = ExploitMaturity.NOT_DEFINED
            return

        # Find highest maturity level
        maturity_levels = {
            ExploitMaturity.NOT_DEFINED: 0,
            ExploitMaturity.UNPROVEN: 1,
            ExploitMaturity.PROOF_OF_CONCEPT: 2,
            ExploitMaturity.FUNCTIONAL: 3,
            ExploitMaturity.HIGH: 4
        }

        max_maturity = ExploitMaturity.NOT_DEFINED
        for exploit in correlation.exploits:
            if maturity_levels.get(exploit.maturity, 0) > maturity_levels.get(max_maturity, 0):
                max_maturity = exploit.maturity

        correlation.exploit_maturity = max_maturity

        # Check if weaponized (HIGH maturity)
        if max_maturity == ExploitMaturity.HIGH:
            correlation.weaponized = True
    
    async def _analyze_threat_actors(self, correlation: ThreatCorrelation):
        """Analyze threat actor associations."""
        if not correlation.threat_actors:
            return
        
        # Extract threat actor characteristics
        for actor in correlation.threat_actors:
            # Check for APT
            if 'apt' in actor.name.lower() or actor.sophistication == 'advanced':
                correlation.apt_associated = True
            
            # Check for ransomware
            if 'ransomware' in actor.motivation.lower():
                correlation.ransomware_associated = True
            
            # Extract targeted industries
            if hasattr(actor, 'targeted_industries'):
                correlation.targeted_industries.extend(actor.targeted_industries)
            
            # Extract targeted regions
            if hasattr(actor, 'targeted_regions'):
                correlation.targeted_regions.extend(actor.targeted_regions)
            
            # Extract active campaigns
            if hasattr(actor, 'active_campaigns'):
                correlation.active_campaigns.extend(actor.active_campaigns)
        
        # Deduplicate
        correlation.targeted_industries = list(set(correlation.targeted_industries))
        correlation.targeted_regions = list(set(correlation.targeted_regions))
        correlation.active_campaigns = list(set(correlation.active_campaigns))
    
    async def _analyze_temporal_context(self, correlation: ThreatCorrelation):
        """Analyze temporal context of threat."""
        now = datetime.utcnow()
        trending_cutoff = now - timedelta(days=self.trending_window_days)
        recent_cutoff = now - timedelta(days=self.recent_activity_days)
        
        # Collect all timestamps
        timestamps = []
        
        # CVE timestamps
        for cve in correlation.cves:
            if hasattr(cve, 'published_date') and cve.published_date:
                timestamps.append(cve.published_date)
        
        # Exploit timestamps
        for exploit in correlation.exploits:
            if hasattr(exploit, 'published_date') and exploit.published_date:
                timestamps.append(exploit.published_date)
            if hasattr(exploit, 'last_seen') and exploit.last_seen:
                timestamps.append(exploit.last_seen)
        
        # IOC timestamps
        for ioc in correlation.iocs:
            if hasattr(ioc, 'first_seen') and ioc.first_seen:
                timestamps.append(ioc.first_seen)
            if hasattr(ioc, 'last_seen') and ioc.last_seen:
                timestamps.append(ioc.last_seen)
        
        if timestamps:
            correlation.first_seen = min(timestamps)
            correlation.last_seen = max(timestamps)
            
            # Check if trending (recent activity)
            recent_timestamps = [ts for ts in timestamps if ts >= trending_cutoff]
            if len(recent_timestamps) >= 3:  # At least 3 recent events
                correlation.trending = True
            
            # Check for exploit in the wild
            if correlation.last_seen and correlation.last_seen >= recent_cutoff:
                if correlation.exploits or correlation.iocs:
                    correlation.exploit_in_wild = True

    async def _analyze_risk_indicators(self, correlation: ThreatCorrelation):
        """Analyze risk indicators."""
        risk_score = 0.0

        # CVE severity
        if correlation.cves:
            cvss_scores = [cve.cvss_v3_score for cve in correlation.cves if hasattr(cve, 'cvss_v3_score') and cve.cvss_v3_score]
            if cvss_scores:
                avg_cvss = sum(cvss_scores) / len(cvss_scores)
                risk_score += (avg_cvss / 10.0) * 0.3  # 30% weight

        # Exploit maturity
        maturity_scores = {
            ExploitMaturity.NOT_DEFINED: 0.0,
            ExploitMaturity.UNPROVEN: 0.2,
            ExploitMaturity.PROOF_OF_CONCEPT: 0.4,
            ExploitMaturity.FUNCTIONAL: 0.7,
            ExploitMaturity.HIGH: 1.0
        }
        if correlation.exploit_maturity:
            risk_score += maturity_scores.get(correlation.exploit_maturity, 0.0) * 0.25  # 25% weight

        # Threat actor sophistication
        if correlation.apt_associated:
            risk_score += 0.2  # 20% weight
        elif correlation.threat_actors:
            risk_score += 0.1  # 10% weight

        # Exploit in wild
        if correlation.exploit_in_wild:
            risk_score += 0.15  # 15% weight

        # Ransomware association
        if correlation.ransomware_associated:
            risk_score += 0.1  # 10% weight

        # Trending
        if correlation.trending:
            risk_score += 0.05  # 5% weight

        # Active campaigns
        if correlation.active_campaigns:
            risk_score += min(len(correlation.active_campaigns) * 0.05, 0.15)  # Up to 15% weight

        # Normalize to 0-1
        risk_score = min(risk_score, 1.0)

        # Determine threat severity
        if risk_score >= 0.8:
            correlation.threat_severity = ThreatSeverity.CRITICAL
        elif risk_score >= 0.6:
            correlation.threat_severity = ThreatSeverity.HIGH
        elif risk_score >= 0.4:
            correlation.threat_severity = ThreatSeverity.MEDIUM
        else:
            correlation.threat_severity = ThreatSeverity.LOW

        correlation.priority_score = risk_score

    async def _calculate_correlation_strength(self, correlation: ThreatCorrelation):
        """Calculate overall correlation strength."""
        score = 0.0
        confidence = 0.0

        # CVE correlation (20% weight)
        if correlation.cves:
            score += 0.2
            confidence += 0.2

        # Exploit correlation (25% weight)
        if correlation.exploits:
            score += 0.25
            confidence += 0.25

            # Bonus for high maturity
            if correlation.exploit_maturity == ExploitMaturity.HIGH:
                score += 0.1

        # Threat actor correlation (20% weight)
        if correlation.threat_actors:
            score += 0.2
            confidence += 0.2

            # Bonus for APT
            if correlation.apt_associated:
                score += 0.1

        # IOC correlation (15% weight)
        if correlation.iocs:
            score += 0.15
            confidence += 0.15

        # MITRE ATT&CK correlation (10% weight)
        if correlation.mitre_techniques:
            score += 0.1
            confidence += 0.1

        # Temporal context (10% weight)
        if correlation.last_seen:
            score += 0.1
            confidence += 0.1

            # Bonus for recent activity
            if correlation.trending:
                score += 0.05

        # Normalize
        score = min(score, 1.0)
        confidence = min(confidence, 1.0)

        # Determine strength
        if score >= self.critical_threshold:
            correlation.correlation_strength = CorrelationStrength.CRITICAL
        elif score >= self.strong_threshold:
            correlation.correlation_strength = CorrelationStrength.STRONG
        elif score >= self.moderate_threshold:
            correlation.correlation_strength = CorrelationStrength.MODERATE
        else:
            correlation.correlation_strength = CorrelationStrength.WEAK

        correlation.correlation_score = score
        correlation.confidence = confidence

    async def _generate_recommendations(self, correlation: ThreatCorrelation):
        """Generate actionable recommendations."""
        recommendations = []

        # Critical severity
        if correlation.threat_severity == ThreatSeverity.CRITICAL:
            recommendations.append("🚨 CRITICAL: Immediate remediation required")
            recommendations.append("Escalate to security leadership immediately")

        # Exploit in wild
        if correlation.exploit_in_wild:
            recommendations.append("⚠️ Active exploitation detected - prioritize patching")
            recommendations.append("Deploy compensating controls immediately")
            recommendations.append("Monitor for IOCs in your environment")

        # Weaponized exploit
        if correlation.weaponized:
            recommendations.append("🎯 Weaponized exploit available - high risk of exploitation")
            recommendations.append("Implement WAF rules and IDS signatures")

        # APT association
        if correlation.apt_associated:
            recommendations.append("🕵️ APT association detected - enhanced monitoring recommended")
            recommendations.append("Review logs for indicators of compromise")
            recommendations.append("Consider threat hunting activities")

        # Ransomware association
        if correlation.ransomware_associated:
            recommendations.append("💀 Ransomware association - verify backup integrity")
            recommendations.append("Test incident response procedures")

        # Trending
        if correlation.trending:
            recommendations.append("📈 Trending vulnerability - expect increased targeting")

        # Active campaigns
        if correlation.active_campaigns:
            campaigns = ", ".join(correlation.active_campaigns[:3])
            recommendations.append(f"🎯 Active campaigns: {campaigns}")
            recommendations.append("Review threat intelligence feeds for campaign TTPs")

        # Targeted industries
        if correlation.targeted_industries:
            industries = ", ".join(correlation.targeted_industries[:3])
            recommendations.append(f"🏢 Targeted industries: {industries}")

        # MITRE ATT&CK techniques
        if correlation.mitre_techniques:
            techniques = ", ".join([t.technique_id for t in correlation.mitre_techniques[:3]])
            recommendations.append(f"🔍 MITRE ATT&CK techniques: {techniques}")
            recommendations.append("Review detection coverage for these techniques")

        # General recommendations
        if correlation.priority_score >= 0.7:
            recommendations.append("Apply security patches within 24 hours")
            recommendations.append("Conduct vulnerability assessment")
        elif correlation.priority_score >= 0.5:
            recommendations.append("Apply security patches within 7 days")
            recommendations.append("Schedule vulnerability assessment")
        else:
            recommendations.append("Apply security patches per normal schedule")

        correlation.recommended_actions = recommendations

    def get_statistics(self) -> Dict:
        """Get correlation engine statistics."""
        cache_hit_rate = 0.0
        if self.total_correlations > 0:
            cache_hit_rate = self.cache_hits / self.total_correlations

        return {
            'total_correlations': self.total_correlations,
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'cache_hit_rate': cache_hit_rate,
            'cache_size': len(self.correlation_cache)
        }

    def clear_cache(self):
        """Clear correlation cache."""
        self.correlation_cache.clear()

    async def batch_correlate(
        self,
        vulnerabilities: List[Tuple[str, str, Dict]]
    ) -> List[ThreatCorrelation]:
        """
        Correlate multiple vulnerabilities in parallel.

        Args:
            vulnerabilities: List of (id, type, threat_data) tuples

        Returns:
            List of ThreatCorrelation objects
        """
        tasks = []
        for vuln_id, vuln_type, threat_data in vulnerabilities:
            task = self.correlate(
                vulnerability_id=vuln_id,
                vulnerability_type=vuln_type,
                cves=threat_data.get('cves'),
                exploits=threat_data.get('exploits'),
                threat_actors=threat_data.get('threat_actors'),
                iocs=threat_data.get('iocs'),
                mitre_techniques=threat_data.get('mitre_techniques')
            )
            tasks.append(task)

        return await asyncio.gather(*tasks)

