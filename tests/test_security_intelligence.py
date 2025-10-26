"""
Tests for Advanced Security Intelligence System (v2.10.0)

Tests for threat correlation, exploit prediction, threat hunting,
and enrichment pipeline.
"""

import pytest
import asyncio
from datetime import datetime, timedelta

from bountybot.threat_intel.correlation_engine import (
    ThreatCorrelationEngine,
    ThreatCorrelation,
    CorrelationStrength
)
from bountybot.threat_intel.exploit_predictor import (
    ExploitPredictor,
    ExploitPrediction,
    ExploitLikelihood
)
from bountybot.threat_intel.threat_hunter import (
    ThreatHunter,
    ThreatHunt,
    HuntingPriority,
    HuntingStatus
)
from bountybot.threat_intel.enrichment_pipeline import (
    ThreatIntelligenceEnrichmentPipeline,
    EnrichedValidation
)
from bountybot.threat_intel.models import (
    CVEData, ExploitData, ThreatActor, IoC, IoCType,
    MitreAttackTechnique, ExploitMaturity, ThreatSeverity
)


class TestThreatCorrelationEngine:
    """Test threat correlation engine."""
    
    def test_init(self):
        """Test engine initialization."""
        engine = ThreatCorrelationEngine()
        assert engine is not None
        assert engine.weak_threshold == 0.3
        assert engine.moderate_threshold == 0.5
        assert engine.strong_threshold == 0.7
        assert engine.critical_threshold == 0.9
    
    @pytest.mark.asyncio
    async def test_correlate_basic(self):
        """Test basic correlation."""
        engine = ThreatCorrelationEngine()
        
        correlation = await engine.correlate(
            vulnerability_id="vuln-001",
            vulnerability_type="SQL Injection"
        )
        
        assert isinstance(correlation, ThreatCorrelation)
        assert correlation.vulnerability_id == "vuln-001"
        assert correlation.vulnerability_type == "SQL Injection"
        assert correlation.correlation_strength in CorrelationStrength
    
    @pytest.mark.asyncio
    async def test_correlate_with_cves(self):
        """Test correlation with CVE data."""
        engine = ThreatCorrelationEngine()

        cve = CVEData(
            cve_id="CVE-2024-1234",
            description="SQL Injection vulnerability",
            published_date=datetime.utcnow(),
            last_modified_date=datetime.utcnow(),
            cvss_v3_score=9.8
        )

        correlation = await engine.correlate(
            vulnerability_id="vuln-001",
            vulnerability_type="SQL Injection",
            cves=[cve]
        )

        assert len(correlation.cves) == 1
        assert correlation.cves[0].cve_id == "CVE-2024-1234"
        assert correlation.correlation_score > 0.0
    
    @pytest.mark.asyncio
    async def test_correlate_with_exploits(self):
        """Test correlation with exploit data."""
        engine = ThreatCorrelationEngine()

        exploit = ExploitData(
            exploit_id="EXP-001",
            title="SQL Injection Exploit",
            description="Test exploit",
            maturity=ExploitMaturity.HIGH
        )

        correlation = await engine.correlate(
            vulnerability_id="vuln-001",
            vulnerability_type="SQL Injection",
            exploits=[exploit]
        )

        assert len(correlation.exploits) == 1
        assert correlation.exploit_maturity == ExploitMaturity.HIGH
        assert correlation.weaponized is True
    
    @pytest.mark.asyncio
    async def test_correlate_with_threat_actors(self):
        """Test correlation with threat actors."""
        engine = ThreatCorrelationEngine()

        actor = ThreatActor(
            actor_id="apt28",
            name="APT28",
            sophistication="advanced",
            motivation="espionage"
        )

        correlation = await engine.correlate(
            vulnerability_id="vuln-001",
            vulnerability_type="SQL Injection",
            threat_actors=[actor]
        )

        assert len(correlation.threat_actors) == 1
        assert correlation.apt_associated is True
    
    @pytest.mark.asyncio
    async def test_correlation_strength_calculation(self):
        """Test correlation strength calculation."""
        engine = ThreatCorrelationEngine()
        
        # Weak correlation (no data)
        correlation1 = await engine.correlate(
            vulnerability_id="vuln-001",
            vulnerability_type="SQL Injection"
        )
        assert correlation1.correlation_strength == CorrelationStrength.WEAK
        
        # Strong correlation (multiple sources)
        cve = CVEData(
            cve_id="CVE-2024-1234",
            description="Test",
            published_date=datetime.utcnow(),
            last_modified_date=datetime.utcnow(),
            cvss_v3_score=9.8
        )
        exploit = ExploitData(
            exploit_id="EXP-001",
            title="Test Exploit",
            description="Test exploit",
            maturity=ExploitMaturity.HIGH
        )
        actor = ThreatActor(
            actor_id="apt28",
            name="APT28",
            sophistication="advanced"
        )
        
        correlation2 = await engine.correlate(
            vulnerability_id="vuln-002",
            vulnerability_type="RCE",
            cves=[cve],
            exploits=[exploit],
            threat_actors=[actor]
        )
        assert correlation2.correlation_strength in [CorrelationStrength.STRONG, CorrelationStrength.CRITICAL]
    
    @pytest.mark.asyncio
    async def test_batch_correlate(self):
        """Test batch correlation."""
        engine = ThreatCorrelationEngine()
        
        vulnerabilities = [
            ("vuln-001", "SQL Injection", {}),
            ("vuln-002", "XSS", {}),
            ("vuln-003", "RCE", {})
        ]
        
        correlations = await engine.batch_correlate(vulnerabilities)
        
        assert len(correlations) == 3
        assert all(isinstance(c, ThreatCorrelation) for c in correlations)
    
    def test_get_statistics(self):
        """Test statistics retrieval."""
        engine = ThreatCorrelationEngine()
        stats = engine.get_statistics()
        
        assert 'total_correlations' in stats
        assert 'cache_hits' in stats
        assert 'cache_misses' in stats
        assert 'cache_hit_rate' in stats


class TestExploitPredictor:
    """Test exploit prediction system."""
    
    def test_init(self):
        """Test predictor initialization."""
        predictor = ExploitPredictor()
        assert predictor is not None
        assert len(predictor.exploit_rates) > 0
        assert len(predictor.weaponization_timelines) > 0
    
    @pytest.mark.asyncio
    async def test_predict_basic(self):
        """Test basic prediction."""
        predictor = ExploitPredictor()
        
        prediction = await predictor.predict(
            vulnerability_id="vuln-001",
            vulnerability_type="SQL Injection"
        )
        
        assert isinstance(prediction, ExploitPrediction)
        assert prediction.vulnerability_id == "vuln-001"
        assert prediction.exploit_likelihood in ExploitLikelihood
        assert 0.0 <= prediction.exploit_probability <= 1.0
    
    @pytest.mark.asyncio
    async def test_predict_high_risk(self):
        """Test prediction for high-risk vulnerability."""
        predictor = ExploitPredictor()
        
        prediction = await predictor.predict(
            vulnerability_id="vuln-001",
            vulnerability_type="Remote Code Execution",
            cvss_score=9.8,
            public_disclosure=True,
            proof_of_concept_available=True,
            vendor_patch_available=False,
            attack_vector="Network",
            privileges_required="None",
            user_interaction="None"
        )
        
        assert prediction.exploit_probability > 0.7
        assert prediction.exploit_likelihood in [
            ExploitLikelihood.HIGH,
            ExploitLikelihood.VERY_HIGH,
            ExploitLikelihood.IMMINENT
        ]
        assert prediction.priority_level in ["high", "critical"]
    
    @pytest.mark.asyncio
    async def test_predict_low_risk(self):
        """Test prediction for low-risk vulnerability."""
        predictor = ExploitPredictor()
        
        prediction = await predictor.predict(
            vulnerability_id="vuln-001",
            vulnerability_type="Information Disclosure",
            cvss_score=3.5,
            public_disclosure=False,
            proof_of_concept_available=False,
            vendor_patch_available=True,
            attack_vector="Local",
            privileges_required="High",
            user_interaction="Required"
        )
        
        assert prediction.exploit_probability < 0.5
        assert prediction.exploit_likelihood in [
            ExploitLikelihood.VERY_LOW,
            ExploitLikelihood.LOW,
            ExploitLikelihood.MODERATE
        ]
    
    @pytest.mark.asyncio
    async def test_weaponization_timeline(self):
        """Test weaponization timeline prediction."""
        predictor = ExploitPredictor()
        
        prediction = await predictor.predict(
            vulnerability_id="vuln-001",
            vulnerability_type="SQL Injection",
            proof_of_concept_available=True
        )
        
        assert prediction.predicted_weaponization_days is not None
        assert prediction.predicted_weaponization_days >= 0
        assert 0.0 <= prediction.weaponization_confidence <= 1.0
    
    @pytest.mark.asyncio
    async def test_batch_predict(self):
        """Test batch prediction."""
        predictor = ExploitPredictor()
        
        vulnerabilities = [
            {'vulnerability_id': 'vuln-001', 'vulnerability_type': 'SQL Injection'},
            {'vulnerability_id': 'vuln-002', 'vulnerability_type': 'XSS'},
            {'vulnerability_id': 'vuln-003', 'vulnerability_type': 'RCE'}
        ]
        
        predictions = await predictor.batch_predict(vulnerabilities)
        
        assert len(predictions) == 3
        assert all(isinstance(p, ExploitPrediction) for p in predictions)


class TestThreatHunter:
    """Test automated threat hunting."""
    
    def test_init(self):
        """Test hunter initialization."""
        hunter = ThreatHunter()
        assert hunter is not None
        assert len(hunter.hunt_templates) > 0
    
    @pytest.mark.asyncio
    async def test_create_hunt(self):
        """Test hunt creation."""
        hunter = ThreatHunter()
        
        hunt = await hunter.create_hunt(
            hunt_name="Test Hunt",
            description="Test hunt description",
            hunt_type="ioc",
            priority=HuntingPriority.HIGH
        )
        
        assert isinstance(hunt, ThreatHunt)
        assert hunt.hunt_name == "Test Hunt"
        assert hunt.status == HuntingStatus.PENDING
        assert hunt.priority == HuntingPriority.HIGH
    
    @pytest.mark.asyncio
    async def test_create_hunt_from_template(self):
        """Test hunt creation from template."""
        hunter = ThreatHunter()
        
        hunt = await hunter.create_hunt_from_template("apt_activity")
        
        assert isinstance(hunt, ThreatHunt)
        assert "APT" in hunt.hunt_name
        assert hunt.priority == HuntingPriority.CRITICAL
    
    @pytest.mark.asyncio
    async def test_execute_hunt(self):
        """Test hunt execution."""
        hunter = ThreatHunter()
        
        hunt = await hunter.create_hunt(
            hunt_name="Test Hunt",
            description="Test",
            hunt_type="ioc"
        )
        
        result = await hunter.execute_hunt(hunt.hunt_id)
        
        assert result.status in [HuntingStatus.FINDINGS_DETECTED, HuntingStatus.NO_FINDINGS]
        assert result.completed_at is not None
    
    def test_get_statistics(self):
        """Test statistics retrieval."""
        hunter = ThreatHunter()
        stats = hunter.get_statistics()
        
        assert 'total_hunts' in stats
        assert 'active_hunts' in stats
        assert 'successful_hunts' in stats


class TestEnrichmentPipeline:
    """Test threat intelligence enrichment pipeline."""
    
    def test_init(self):
        """Test pipeline initialization."""
        pipeline = ThreatIntelligenceEnrichmentPipeline()
        assert pipeline is not None
        assert pipeline.correlation_engine is not None
        assert pipeline.exploit_predictor is not None
        assert pipeline.threat_hunter is not None
    
    @pytest.mark.asyncio
    async def test_enrich_basic(self):
        """Test basic enrichment."""
        pipeline = ThreatIntelligenceEnrichmentPipeline()
        
        enriched = await pipeline.enrich(
            validation_id="val-001",
            vulnerability_type="SQL Injection",
            severity="high"
        )
        
        assert isinstance(enriched, EnrichedValidation)
        assert enriched.validation_id == "val-001"
        assert enriched.vulnerability_type == "SQL Injection"
        assert len(enriched.enrichment_sources) > 0
    
    @pytest.mark.asyncio
    async def test_enrich_with_correlation(self):
        """Test enrichment with correlation."""
        pipeline = ThreatIntelligenceEnrichmentPipeline()
        
        enriched = await pipeline.enrich(
            validation_id="val-001",
            vulnerability_type="SQL Injection",
            severity="high",
            cvss_score=9.8
        )
        
        assert enriched.threat_correlation is not None
        assert 'correlation' in enriched.enrichment_sources
    
    @pytest.mark.asyncio
    async def test_enrich_with_prediction(self):
        """Test enrichment with prediction."""
        pipeline = ThreatIntelligenceEnrichmentPipeline()
        
        enriched = await pipeline.enrich(
            validation_id="val-001",
            vulnerability_type="Remote Code Execution",
            severity="critical",
            cvss_score=9.8,
            public_disclosure=True
        )
        
        assert enriched.exploit_prediction is not None
        assert 'prediction' in enriched.enrichment_sources
    
    @pytest.mark.asyncio
    async def test_batch_enrich(self):
        """Test batch enrichment."""
        pipeline = ThreatIntelligenceEnrichmentPipeline()
        
        validations = [
            {'validation_id': 'val-001', 'vulnerability_type': 'SQL Injection', 'severity': 'high'},
            {'validation_id': 'val-002', 'vulnerability_type': 'XSS', 'severity': 'medium'},
            {'validation_id': 'val-003', 'vulnerability_type': 'RCE', 'severity': 'critical'}
        ]
        
        enriched_list = await pipeline.batch_enrich(validations)
        
        assert len(enriched_list) == 3
        assert all(isinstance(e, EnrichedValidation) for e in enriched_list)
    
    def test_get_statistics(self):
        """Test statistics retrieval."""
        pipeline = ThreatIntelligenceEnrichmentPipeline()
        stats = pipeline.get_statistics()
        
        assert 'total_enrichments' in stats
        assert 'successful_enrichments' in stats
        assert 'correlation_stats' in stats
        assert 'prediction_stats' in stats
        assert 'hunting_stats' in stats
