"""
Tests for Threat Intelligence Module
"""

import unittest
import tempfile
import shutil
from datetime import datetime, timedelta

from bountybot.threat_intel import (
    CVEEnricher,
    ExploitCorrelator,
    ThreatFeedManager,
    MitreMapper,
    IoC_Manager,
    VulnerabilityIntelligenceEngine,
    ThreatActorProfiler,
    RiskContextualizer,
    ThreatFeed,
    IoC,
    IoCType,
    ThreatSeverity,
    VulnerabilityStatus
)


class TestCVEEnricher(unittest.TestCase):
    """Test CVE enrichment."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.enricher = CVEEnricher(cache_dir=self.temp_dir)
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_extract_cve_ids(self):
        """Test CVE ID extraction."""
        text = "Found CVE-2021-44228 and CVE-2014-0160 in the system"
        cve_ids = self.enricher.extract_cve_ids(text)
        
        self.assertEqual(len(cve_ids), 2)
        self.assertIn("CVE-2021-44228", cve_ids)
        self.assertIn("CVE-2014-0160", cve_ids)
    
    def test_enrich_cve(self):
        """Test CVE enrichment."""
        cve_data = self.enricher.enrich_cve("CVE-2021-44228")
        
        self.assertIsNotNone(cve_data)
        self.assertEqual(cve_data.cve_id, "CVE-2021-44228")
        self.assertIsNotNone(cve_data.cvss_v3_score)
        self.assertTrue(cve_data.patch_available)
    
    def test_validate_cvss_score(self):
        """Test CVSS score validation."""
        result = self.enricher.validate_cvss_score("CVE-2021-44228", 10.0)
        
        self.assertTrue(result['valid'])
        self.assertEqual(result['official_score'], 10.0)


class TestExploitCorrelator(unittest.TestCase):
    """Test exploit correlation."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.correlator = ExploitCorrelator(cache_dir=self.temp_dir)
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_find_exploits(self):
        """Test finding exploits for CVE."""
        exploits = self.correlator.find_exploits_for_cve("CVE-2021-44228")
        
        self.assertGreater(len(exploits), 0)
        self.assertTrue(any(e.source == "ExploitDB" for e in exploits))
    
    def test_exploit_summary(self):
        """Test exploit summary."""
        summary = self.correlator.get_exploit_summary("CVE-2021-44228")
        
        self.assertTrue(summary['exploit_available'])
        self.assertGreater(summary['exploit_count'], 0)


class TestThreatFeedManager(unittest.TestCase):
    """Test threat feed management."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.manager = ThreatFeedManager(config_dir=self.temp_dir)
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_add_feed(self):
        """Test adding a threat feed."""
        feed = ThreatFeed(
            feed_id="test_feed",
            name="Test Feed",
            feed_type="JSON",
            url="https://example.com/feed",
            enabled=True
        )
        
        result = self.manager.add_feed(feed)
        self.assertTrue(result)
        self.assertIn("test_feed", self.manager.feeds)
    
    def test_update_feed(self):
        """Test updating a feed."""
        feed = ThreatFeed(
            feed_id="test_feed",
            name="Test Feed",
            feed_type="JSON",
            url="https://example.com/feed",
            enabled=True
        )
        
        self.manager.add_feed(feed)
        result = self.manager.update_feed("test_feed")
        
        self.assertTrue(result['success'])
        self.assertGreater(result['total'], 0)


class TestMitreMapper(unittest.TestCase):
    """Test MITRE ATT&CK mapping."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.mapper = MitreMapper(data_dir=self.temp_dir)
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_map_vulnerability(self):
        """Test mapping vulnerability to techniques."""
        description = "Remote code execution vulnerability allowing command injection"
        techniques = self.mapper.map_vulnerability_to_techniques("CVE-2021-44228", description)
        
        self.assertGreater(len(techniques), 0)
        self.assertTrue(any(t.technique_id == "T1190" for t in techniques))
    
    def test_get_technique(self):
        """Test getting technique by ID."""
        technique = self.mapper.get_technique("T1190")
        
        self.assertIsNotNone(technique)
        self.assertEqual(technique.technique_id, "T1190")
        self.assertEqual(technique.tactic, "Initial Access")


class TestIoCManager(unittest.TestCase):
    """Test IoC management."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.manager = IoC_Manager(storage_dir=self.temp_dir)
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_extract_iocs(self):
        """Test IoC extraction from text."""
        text = "Malicious IP 192.0.2.1 and domain malicious-example.com found"
        iocs = self.manager.extract_iocs_from_text(text)
        
        self.assertGreater(len(iocs[IoCType.IP_ADDRESS]), 0)
        self.assertGreater(len(iocs[IoCType.DOMAIN]), 0)
    
    def test_add_ioc(self):
        """Test adding an IoC."""
        ioc = IoC(
            ioc_id="test_ioc",
            ioc_type=IoCType.IP_ADDRESS,
            value="192.0.2.1",
            severity=ThreatSeverity.HIGH,
            confidence=0.9
        )
        
        result = self.manager.add_ioc(ioc)
        self.assertTrue(result)
        self.assertIn("test_ioc", self.manager.iocs)
    
    def test_check_ioc(self):
        """Test checking if value is an IoC."""
        ioc = IoC(
            ioc_id="test_ioc",
            ioc_type=IoCType.IP_ADDRESS,
            value="192.0.2.1",
            severity=ThreatSeverity.HIGH,
            confidence=0.9
        )
        
        self.manager.add_ioc(ioc)
        result = self.manager.check_ioc("192.0.2.1", IoCType.IP_ADDRESS)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.value, "192.0.2.1")


class TestVulnerabilityIntelligence(unittest.TestCase):
    """Test vulnerability intelligence."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.engine = VulnerabilityIntelligenceEngine(data_dir=self.temp_dir)
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_track_vulnerability(self):
        """Test tracking a vulnerability."""
        vuln = self.engine.track_vulnerability(
            "CVE-2021-44228",
            status=VulnerabilityStatus.ACTIVELY_EXPLOITED,
            exploit_available=True,
            risk_score=10.0
        )
        
        self.assertEqual(vuln.vuln_id, "CVE-2021-44228")
        self.assertTrue(vuln.exploit_available)
    
    def test_detect_zero_day(self):
        """Test zero-day detection."""
        self.engine.track_vulnerability(
            "CVE-TEST-0001",
            status=VulnerabilityStatus.DISCOVERED,
            exploit_available=True,
            actively_exploited=True
        )
        
        result = self.engine.detect_zero_day("CVE-TEST-0001")
        self.assertTrue(result['is_zero_day'])
    
    def test_trending_score(self):
        """Test trending score calculation."""
        self.engine.track_vulnerability(
            "CVE-TEST-0002",
            social_media_mentions=500,
            exploit_available=True
        )
        
        score = self.engine.calculate_trending_score("CVE-TEST-0002")
        self.assertGreater(score, 0.0)


class TestThreatActorProfiler(unittest.TestCase):
    """Test threat actor profiling."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.profiler = ThreatActorProfiler(data_dir=self.temp_dir)
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_get_actor(self):
        """Test getting threat actor."""
        actor = self.profiler.get_actor("APT28")
        
        self.assertIsNotNone(actor)
        self.assertEqual(actor.actor_id, "APT28")
    
    def test_attribute_attack(self):
        """Test attack attribution."""
        attributions = self.profiler.attribute_attack(
            techniques=["T1190", "T1059"],
            tools=["X-Agent"],
            target_industry="Government"
        )
        
        self.assertGreater(len(attributions), 0)
        self.assertTrue(any(a['actor_id'] == "APT28" for a in attributions))


class TestRiskContextualizer(unittest.TestCase):
    """Test risk contextualization."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.contextualizer = RiskContextualizer()
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_contextualize_vulnerability(self):
        """Test vulnerability contextualization."""
        context = self.contextualizer.contextualize_vulnerability(
            cve_id="CVE-2021-44228",
            base_cvss_score=10.0,
            description="Remote code execution in Log4j"
        )
        
        self.assertEqual(context['cve_id'], "CVE-2021-44228")
        self.assertGreaterEqual(context['contextualized_score'], context['base_cvss_score'])
        self.assertIn('risk_factors', context)
        self.assertIn('recommendations', context)
    
    def test_assess_threat_landscape(self):
        """Test threat landscape assessment."""
        assessment = self.contextualizer.assess_threat_landscape(
            industry="Government",
            country="USA"
        )
        
        self.assertIn('threat_actors', assessment)
        self.assertIn('overall_risk', assessment)


if __name__ == '__main__':
    unittest.main()

