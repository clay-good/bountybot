"""
Threat Intelligence Enrichment Pipeline

Enriches vulnerability validations with comprehensive threat intelligence
from multiple sources including CVEs, exploits, threat actors, IOCs, and MITRE ATT&CK.
"""

import asyncio
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from .correlation_engine import ThreatCorrelationEngine, ThreatCorrelation
from .exploit_predictor import ExploitPredictor, ExploitPrediction
from .threat_hunter import ThreatHunter, ThreatHunt
from .cve_enricher import CVEEnricher
from .exploit_correlator import ExploitCorrelator
from .mitre_mapper import MitreMapper
from .ioc_manager import IoC_Manager
from .threat_actor_profiler import ThreatActorProfiler


@dataclass
class EnrichedValidation:
    """Validation enriched with threat intelligence."""
    
    # Original validation data
    validation_id: str
    vulnerability_type: str
    severity: str
    
    # Threat correlation
    threat_correlation: Optional[ThreatCorrelation] = None
    
    # Exploit prediction
    exploit_prediction: Optional[ExploitPrediction] = None
    
    # Threat hunts
    threat_hunts: List[ThreatHunt] = field(default_factory=list)
    
    # Enrichment metadata
    enrichment_sources: List[str] = field(default_factory=list)
    enrichment_timestamp: datetime = field(default_factory=datetime.utcnow)
    enrichment_confidence: float = 0.0
    
    # Aggregated risk assessment
    overall_risk_score: float = 0.0
    risk_level: str = "low"
    priority_score: float = 0.0
    
    # Actionable intelligence
    recommended_actions: List[str] = field(default_factory=list)
    mitigation_timeline: str = "standard"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'validation_id': self.validation_id,
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity,
            'threat_correlation': self.threat_correlation.to_dict() if self.threat_correlation else None,
            'exploit_prediction': self.exploit_prediction.to_dict() if self.exploit_prediction else None,
            'threat_hunts': [hunt.to_dict() for hunt in self.threat_hunts],
            'enrichment_sources': self.enrichment_sources,
            'enrichment_timestamp': self.enrichment_timestamp.isoformat(),
            'enrichment_confidence': self.enrichment_confidence,
            'overall_risk_score': self.overall_risk_score,
            'risk_level': self.risk_level,
            'priority_score': self.priority_score,
            'recommended_actions': self.recommended_actions,
            'mitigation_timeline': self.mitigation_timeline
        }


class ThreatIntelligenceEnrichmentPipeline:
    """
    Comprehensive threat intelligence enrichment pipeline.
    
    Enriches vulnerability validations with threat intelligence from multiple
    sources to provide comprehensive security context and actionable intelligence.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize enrichment pipeline."""
        self.config = config or {}

        # Initialize components
        self.correlation_engine = ThreatCorrelationEngine(
            self.config.get('correlation', {})
        )
        self.exploit_predictor = ExploitPredictor(
            self.config.get('prediction', {})
        )
        self.threat_hunter = ThreatHunter(
            self.config.get('hunting', {})
        )
        
        # Initialize enrichment sources
        self.cve_enricher = CVEEnricher()
        self.exploit_correlator = ExploitCorrelator()
        self.mitre_mapper = MitreMapper()
        self.ioc_manager = IoC_Manager()
        self.threat_actor_profiler = ThreatActorProfiler()
        
        # Pipeline configuration
        self.enable_correlation = self.config.get('enable_correlation', True)
        self.enable_prediction = self.config.get('enable_prediction', True)
        self.enable_hunting = self.config.get('enable_hunting', False)  # Disabled by default
        
        # Statistics
        self.total_enrichments = 0
        self.successful_enrichments = 0
    
    async def enrich(
        self,
        validation_id: str,
        vulnerability_type: str,
        severity: str,
        cve_ids: Optional[List[str]] = None,
        affected_products: Optional[List[str]] = None,
        cvss_score: Optional[float] = None,
        attack_vector: Optional[str] = None,
        privileges_required: Optional[str] = None,
        user_interaction: Optional[str] = None,
        public_disclosure: bool = False,
        vendor_patch_available: bool = False,
        create_threat_hunt: bool = False
    ) -> EnrichedValidation:
        """
        Enrich validation with threat intelligence.
        
        Args:
            validation_id: Unique validation identifier
            vulnerability_type: Type of vulnerability
            severity: Severity level
            cve_ids: Related CVE IDs
            affected_products: List of affected products
            cvss_score: CVSS score
            attack_vector: Attack vector
            privileges_required: Privileges required
            user_interaction: User interaction required
            public_disclosure: Whether publicly disclosed
            vendor_patch_available: Whether patch is available
            create_threat_hunt: Whether to create threat hunt
        
        Returns:
            EnrichedValidation with comprehensive threat intelligence
        """
        self.total_enrichments += 1
        
        enriched = EnrichedValidation(
            validation_id=validation_id,
            vulnerability_type=vulnerability_type,
            severity=severity
        )
        
        # Gather threat intelligence from all sources
        threat_data = await self._gather_threat_intelligence(
            vulnerability_type=vulnerability_type,
            cve_ids=cve_ids,
            affected_products=affected_products
        )
        
        # Perform threat correlation
        if self.enable_correlation:
            enriched.threat_correlation = await self.correlation_engine.correlate(
                vulnerability_id=validation_id,
                vulnerability_type=vulnerability_type,
                cves=threat_data.get('cves'),
                exploits=threat_data.get('exploits'),
                threat_actors=threat_data.get('threat_actors'),
                iocs=threat_data.get('iocs'),
                mitre_techniques=threat_data.get('mitre_techniques')
            )
            enriched.enrichment_sources.append('correlation')
        
        # Perform exploit prediction
        if self.enable_prediction:
            # Check for existing exploits
            proof_of_concept_available = False
            if threat_data.get('exploits'):
                proof_of_concept_available = True
            
            enriched.exploit_prediction = await self.exploit_predictor.predict(
                vulnerability_id=validation_id,
                vulnerability_type=vulnerability_type,
                cvss_score=cvss_score,
                cve_data=threat_data.get('cves', [None])[0] if threat_data.get('cves') else None,
                exploit_data=threat_data.get('exploits'),
                public_disclosure=public_disclosure,
                proof_of_concept_available=proof_of_concept_available,
                vendor_patch_available=vendor_patch_available,
                affected_products=affected_products,
                attack_vector=attack_vector,
                privileges_required=privileges_required,
                user_interaction=user_interaction
            )
            enriched.enrichment_sources.append('prediction')
        
        # Create threat hunt if requested
        if self.enable_hunting and (create_threat_hunt or self._should_create_hunt(enriched)):
            hunt = await self.threat_hunter.create_hunt_from_vulnerability(
                vulnerability_id=validation_id,
                vulnerability_type=vulnerability_type,
                iocs=threat_data.get('iocs'),
                ttps=threat_data.get('mitre_techniques'),
                threat_actors=threat_data.get('threat_actors')
            )
            enriched.threat_hunts.append(hunt)
            enriched.enrichment_sources.append('hunting')
        
        # Calculate aggregated risk assessment
        self._calculate_risk_assessment(enriched)
        
        # Generate actionable intelligence
        self._generate_actionable_intelligence(enriched)
        
        # Calculate enrichment confidence
        enriched.enrichment_confidence = self._calculate_enrichment_confidence(enriched)
        
        self.successful_enrichments += 1
        
        return enriched
    
    async def _gather_threat_intelligence(
        self,
        vulnerability_type: str,
        cve_ids: Optional[List[str]],
        affected_products: Optional[List[str]]
    ) -> Dict:
        """Gather threat intelligence from all sources."""
        threat_data = {
            'cves': [],
            'exploits': [],
            'threat_actors': [],
            'iocs': [],
            'mitre_techniques': []
        }
        
        # Gather CVE data
        if cve_ids:
            for cve_id in cve_ids:
                try:
                    cve_data = await self.cve_enricher.enrich(cve_id)
                    if cve_data:
                        threat_data['cves'].append(cve_data)
                except Exception:
                    pass
        
        # Gather exploit data
        try:
            exploits = await self.exploit_correlator.find_exploits(
                vulnerability_type=vulnerability_type,
                cve_ids=cve_ids
            )
            threat_data['exploits'] = exploits
        except Exception:
            pass
        
        # Map to MITRE ATT&CK
        try:
            techniques = await self.mitre_mapper.map_vulnerability(vulnerability_type)
            threat_data['mitre_techniques'] = techniques
        except Exception:
            pass
        
        # Gather IOCs
        try:
            iocs = await self.ioc_manager.find_related_iocs(
                vulnerability_type=vulnerability_type,
                cve_ids=cve_ids
            )
            threat_data['iocs'] = iocs
        except Exception:
            pass
        
        # Profile threat actors
        try:
            actors = await self.threat_actor_profiler.find_actors(
                vulnerability_type=vulnerability_type,
                cve_ids=cve_ids
            )
            threat_data['threat_actors'] = actors
        except Exception:
            pass
        
        return threat_data
    
    def _should_create_hunt(self, enriched: EnrichedValidation) -> bool:
        """Determine if threat hunt should be created."""
        # Create hunt for high-risk vulnerabilities
        if enriched.threat_correlation:
            if enriched.threat_correlation.apt_associated:
                return True
            if enriched.threat_correlation.exploit_in_wild:
                return True
            if enriched.threat_correlation.ransomware_associated:
                return True
        
        if enriched.exploit_prediction:
            if enriched.exploit_prediction.exploit_probability >= 0.8:
                return True
        
        return False
    
    def _calculate_risk_assessment(self, enriched: EnrichedValidation):
        """Calculate aggregated risk assessment."""
        risk_scores = []
        
        # Correlation risk
        if enriched.threat_correlation:
            risk_scores.append(enriched.threat_correlation.priority_score)
        
        # Prediction risk
        if enriched.exploit_prediction:
            risk_scores.append(enriched.exploit_prediction.exploit_probability)
        
        # Calculate overall risk
        if risk_scores:
            enriched.overall_risk_score = sum(risk_scores) / len(risk_scores)
        
        # Determine risk level
        if enriched.overall_risk_score >= 0.8:
            enriched.risk_level = "critical"
        elif enriched.overall_risk_score >= 0.6:
            enriched.risk_level = "high"
        elif enriched.overall_risk_score >= 0.4:
            enriched.risk_level = "medium"
        else:
            enriched.risk_level = "low"
        
        # Calculate priority score (combines risk with urgency)
        enriched.priority_score = enriched.overall_risk_score

    def _generate_actionable_intelligence(self, enriched: EnrichedValidation):
        """Generate actionable intelligence and recommendations."""
        recommendations = []

        # Aggregate recommendations from all sources
        if enriched.threat_correlation:
            recommendations.extend(enriched.threat_correlation.recommended_actions)

        # Add prediction-based recommendations
        if enriched.exploit_prediction:
            if enriched.exploit_prediction.exploit_likelihood.value in ['imminent', 'very_high']:
                recommendations.append("🚨 Exploit highly likely - immediate action required")

            if enriched.exploit_prediction.predicted_weaponization_days is not None:
                days = enriched.exploit_prediction.predicted_weaponization_days
                if days <= 7:
                    recommendations.append(f"⏰ Weaponization predicted in {days} days")
                elif days <= 30:
                    recommendations.append(f"⏰ Weaponization predicted in ~{days} days")

        # Add hunt-based recommendations
        if enriched.threat_hunts:
            recommendations.append(f"🔍 {len(enriched.threat_hunts)} threat hunt(s) initiated")

        # Determine mitigation timeline
        if enriched.risk_level == "critical":
            enriched.mitigation_timeline = "immediate (24 hours)"
        elif enriched.risk_level == "high":
            enriched.mitigation_timeline = "urgent (7 days)"
        elif enriched.risk_level == "medium":
            enriched.mitigation_timeline = "standard (30 days)"
        else:
            enriched.mitigation_timeline = "routine (90 days)"

        # Deduplicate and prioritize recommendations
        enriched.recommended_actions = list(dict.fromkeys(recommendations))[:10]

    def _calculate_enrichment_confidence(self, enriched: EnrichedValidation) -> float:
        """Calculate confidence in enrichment data."""
        confidence_scores = []

        # Correlation confidence
        if enriched.threat_correlation:
            confidence_scores.append(enriched.threat_correlation.confidence)

        # Prediction confidence
        if enriched.exploit_prediction:
            confidence_scores.append(enriched.exploit_prediction.weaponization_confidence)

        # Source diversity bonus
        source_bonus = min(len(enriched.enrichment_sources) * 0.1, 0.3)

        if confidence_scores:
            base_confidence = sum(confidence_scores) / len(confidence_scores)
            return min(base_confidence + source_bonus, 1.0)

        return 0.5  # Default confidence

    async def batch_enrich(
        self,
        validations: List[Dict]
    ) -> List[EnrichedValidation]:
        """
        Enrich multiple validations in parallel.

        Args:
            validations: List of validation data dictionaries

        Returns:
            List of EnrichedValidation objects
        """
        tasks = [self.enrich(**validation) for validation in validations]
        return await asyncio.gather(*tasks)

    def get_statistics(self) -> Dict:
        """Get enrichment pipeline statistics."""
        success_rate = 0.0
        if self.total_enrichments > 0:
            success_rate = self.successful_enrichments / self.total_enrichments

        return {
            'total_enrichments': self.total_enrichments,
            'successful_enrichments': self.successful_enrichments,
            'success_rate': success_rate,
            'correlation_stats': self.correlation_engine.get_statistics(),
            'prediction_stats': self.exploit_predictor.get_statistics(),
            'hunting_stats': self.threat_hunter.get_statistics()
        }

    async def enrich_with_auto_hunt(
        self,
        validation_id: str,
        vulnerability_type: str,
        severity: str,
        **kwargs
    ) -> EnrichedValidation:
        """
        Enrich validation and automatically execute threat hunt if needed.

        Args:
            validation_id: Validation identifier
            vulnerability_type: Vulnerability type
            severity: Severity level
            **kwargs: Additional enrichment parameters

        Returns:
            EnrichedValidation with executed threat hunts
        """
        # Enrich validation
        enriched = await self.enrich(
            validation_id=validation_id,
            vulnerability_type=vulnerability_type,
            severity=severity,
            create_threat_hunt=True,
            **kwargs
        )

        # Execute threat hunts if created
        if enriched.threat_hunts:
            hunt_ids = [hunt.hunt_id for hunt in enriched.threat_hunts]
            executed_hunts = await self.threat_hunter.batch_execute_hunts(hunt_ids)
            enriched.threat_hunts = executed_hunts

        return enriched
