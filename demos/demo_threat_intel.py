"""
Threat Intelligence & Vulnerability Enrichment Demo

Demonstrates comprehensive threat intelligence capabilities.
"""

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


def print_section(title: str):
    """Print section header."""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}\n")


def demo_cve_enrichment():
    """Demonstrate CVE enrichment."""
    print_section("CVE/NVD ENRICHMENT")
    
    temp_dir = tempfile.mkdtemp()
    enricher = CVEEnricher(cache_dir=temp_dir)
    
    print("1. Extracting CVE IDs from text:")
    text = "Found CVE-2021-44228 (Log4Shell) and CVE-2014-0160 (Heartbleed) vulnerabilities"
    cve_ids = enricher.extract_cve_ids(text)
    print(f"   Found {len(cve_ids)} CVEs: {', '.join(cve_ids)}")
    
    print("\n2. Enriching CVE-2021-44228 (Log4Shell):")
    cve_data = enricher.enrich_cve("CVE-2021-44228")
    if cve_data:
        print(f"   CVE ID: {cve_data.cve_id}")
        print(f"   CVSS v3 Score: {cve_data.cvss_v3_score}")
        print(f"   Published: {cve_data.published_date.strftime('%Y-%m-%d')}")
        print(f"   CWE IDs: {', '.join(cve_data.cwe_ids)}")
        print(f"   Patch Available: {'✅ Yes' if cve_data.patch_available else '❌ No'}")
        print(f"   Affected Products: {len(cve_data.affected_products)}")
    
    print("\n3. Validating CVSS Score:")
    validation = enricher.validate_cvss_score("CVE-2021-44228", 10.0)
    print(f"   Reported Score: {validation['reported_score']}")
    print(f"   Official Score: {validation['official_score']}")
    print(f"   Valid: {'✅ Yes' if validation['valid'] else '❌ No'}")
    
    shutil.rmtree(temp_dir, ignore_errors=True)


def demo_exploit_correlation():
    """Demonstrate exploit correlation."""
    print_section("EXPLOIT DATABASE CORRELATION")
    
    temp_dir = tempfile.mkdtemp()
    correlator = ExploitCorrelator(cache_dir=temp_dir)
    
    print("1. Finding exploits for CVE-2021-44228:")
    exploits = correlator.find_exploits_for_cve("CVE-2021-44228")
    print(f"   Found {len(exploits)} exploits")
    
    for exploit in exploits[:3]:
        print(f"\n   Exploit: {exploit.title}")
        print(f"     Source: {exploit.source}")
        print(f"     Maturity: {exploit.maturity.value}")
        print(f"     Verified: {'✅ Yes' if exploit.verified else '❌ No'}")
        print(f"     Code Available: {'✅ Yes' if exploit.code_available else '❌ No'}")
    
    print("\n2. Exploit Summary:")
    summary = correlator.get_exploit_summary("CVE-2021-44228")
    print(f"   Exploit Available: {'✅ Yes' if summary['exploit_available'] else '❌ No'}")
    print(f"   Total Exploits: {summary['exploit_count']}")
    print(f"   Public Exploits: {summary['public_exploits']}")
    print(f"   Metasploit Modules: {summary['metasploit_modules']}")
    print(f"   Highest Maturity: {summary['highest_maturity']}")
    
    print("\n3. Weaponization Check:")
    weaponization = correlator.check_weaponization("CVE-2021-44228")
    print(f"   Weaponized: {'✅ Yes' if weaponization['weaponized'] else '❌ No'}")
    if weaponization['weaponization_date']:
        print(f"   Weaponization Date: {weaponization['weaponization_date']}")
    
    shutil.rmtree(temp_dir, ignore_errors=True)


def demo_threat_feeds():
    """Demonstrate threat feed management."""
    print_section("THREAT INTELLIGENCE FEEDS")
    
    temp_dir = tempfile.mkdtemp()
    manager = ThreatFeedManager(config_dir=temp_dir)
    
    print("1. Adding Threat Feed:")
    feed = ThreatFeed(
        feed_id="alienvault_otx",
        name="AlienVault OTX",
        feed_type="STIX",
        url="https://otx.alienvault.com/api/v1/pulses/subscribed",
        enabled=True,
        priority=8,
        min_confidence=0.7
    )
    
    manager.add_feed(feed)
    print(f"   ✅ Added feed: {feed.name}")
    
    print("\n2. Updating Feed:")
    result = manager.update_feed("alienvault_otx")
    print(f"   Success: {'✅ Yes' if result['success'] else '❌ No'}")
    print(f"   Indicators Added: {result['added']}")
    print(f"   Indicators Updated: {result['updated']}")
    print(f"   Total Indicators: {result['total']}")
    
    print("\n3. Feed Statistics:")
    stats = manager.get_feed_stats()
    print(f"   Total Feeds: {stats['total_feeds']}")
    print(f"   Enabled Feeds: {stats['enabled_feeds']}")
    print(f"   Total Indicators: {stats['total_indicators']}")
    print(f"   Indicators by Type:")
    for ioc_type, count in stats['indicators_by_type'].items():
        print(f"     {ioc_type}: {count}")
    
    shutil.rmtree(temp_dir, ignore_errors=True)


def demo_mitre_mapping():
    """Demonstrate MITRE ATT&CK mapping."""
    print_section("MITRE ATT&CK MAPPING")
    
    temp_dir = tempfile.mkdtemp()
    mapper = MitreMapper(data_dir=temp_dir)
    
    print("1. Mapping Vulnerability to Techniques:")
    description = "Remote code execution vulnerability allowing command injection via JNDI"
    techniques = mapper.map_vulnerability_to_techniques("CVE-2021-44228", description)
    
    print(f"   Found {len(techniques)} relevant techniques:")
    for technique in techniques:
        print(f"\n   {technique.technique_id}: {technique.name}")
        print(f"     Tactic: {technique.tactic}")
        print(f"     Platforms: {', '.join(technique.platforms)}")
    
    print("\n2. Kill Chain Analysis:")
    technique_ids = [t.technique_id for t in techniques]
    kill_chain = mapper.get_kill_chain_analysis(technique_ids)
    print(f"   Techniques: {kill_chain['techniques_count']}")
    print(f"   Tactics Covered: {kill_chain['tactics_covered']}")
    print(f"   Kill Chain Stages: {', '.join(kill_chain['kill_chain_stages'])}")
    print(f"   Coverage: {kill_chain['coverage_percentage']:.1f}%")
    
    shutil.rmtree(temp_dir, ignore_errors=True)


def demo_ioc_management():
    """Demonstrate IoC management."""
    print_section("IOC MANAGEMENT")
    
    temp_dir = tempfile.mkdtemp()
    manager = IoC_Manager(storage_dir=temp_dir)
    
    print("1. Extracting IoCs from text:")
    text = "Malicious traffic from 192.0.2.1 to malicious-example.com, hash: d41d8cd98f00b204e9800998ecf8427e"
    iocs = manager.extract_iocs_from_text(text)
    
    for ioc_type, values in iocs.items():
        if values:
            print(f"   {ioc_type.value}: {', '.join(values)}")
    
    print("\n2. Adding Known Malicious IoC:")
    ioc = IoC(
        ioc_id="ioc_001",
        ioc_type=IoCType.IP_ADDRESS,
        value="192.0.2.1",
        description="Known C2 server",
        severity=ThreatSeverity.HIGH,
        confidence=0.95,
        threat_actor="APT28",
        campaign="Operation XYZ",
        reputation_score=-0.9,
        sources=["AlienVault OTX", "VirusTotal"]
    )
    
    manager.add_ioc(ioc)
    print(f"   ✅ Added IoC: {ioc.value}")
    
    print("\n3. Checking IP Reputation:")
    reputation = manager.get_reputation("192.0.2.1", IoCType.IP_ADDRESS)
    print(f"   Known IoC: {'✅ Yes' if reputation['known_ioc'] else '❌ No'}")
    if reputation['known_ioc']:
        print(f"   Reputation Score: {reputation['reputation_score']:.2f}")
        print(f"   Severity: {reputation['severity']}")
        print(f"   Threat Actor: {reputation['threat_actor']}")
        print(f"   Campaign: {reputation['campaign']}")
    
    shutil.rmtree(temp_dir, ignore_errors=True)


def demo_vulnerability_intelligence():
    """Demonstrate vulnerability intelligence."""
    print_section("VULNERABILITY INTELLIGENCE")
    
    temp_dir = tempfile.mkdtemp()
    engine = VulnerabilityIntelligenceEngine(data_dir=temp_dir)
    
    print("1. Tracking Vulnerability:")
    vuln = engine.track_vulnerability(
        "CVE-2021-44228",
        status=VulnerabilityStatus.ACTIVELY_EXPLOITED,
        exploit_available=True,
        exploit_public=True,
        actively_exploited=True,
        exploit_in_wild=True,
        social_media_mentions=5000,
        dark_web_mentions=150,
        risk_score=10.0,
        affected_systems=100000
    )
    
    print(f"   Vulnerability: {vuln.vuln_id}")
    print(f"   Status: {vuln.status.value}")
    print(f"   Actively Exploited: {'✅ Yes' if vuln.actively_exploited else '❌ No'}")
    
    print("\n2. Trending Score:")
    trending_score = engine.calculate_trending_score("CVE-2021-44228")
    print(f"   Trending Score: {trending_score:.2f} / 1.0")
    if trending_score > 0.7:
        print(f"   Status: 🔥 HIGHLY TRENDING")
    
    print("\n3. Zero-Day Detection:")
    zero_day = engine.detect_zero_day("CVE-2021-44228")
    print(f"   Is Zero-Day: {'✅ Yes' if zero_day['is_zero_day'] else '❌ No'}")
    print(f"   Confidence: {zero_day['confidence']:.0%}")
    
    print("\n4. Exploit Likelihood Prediction:")
    likelihood = engine.predict_exploit_likelihood("CVE-2021-44228")
    print(f"   Exploit Likelihood: {likelihood['likelihood']:.0%}")
    print(f"   Confidence: {likelihood['confidence']:.0%}")
    
    shutil.rmtree(temp_dir, ignore_errors=True)


def demo_threat_actor_profiling():
    """Demonstrate threat actor profiling."""
    print_section("THREAT ACTOR PROFILING")
    
    temp_dir = tempfile.mkdtemp()
    profiler = ThreatActorProfiler(data_dir=temp_dir)
    
    print("1. Known Threat Actors:")
    actors = profiler.search_actors()
    print(f"   Total Actors: {len(actors)}")
    
    for actor in actors[:3]:
        print(f"\n   {actor.name} ({actor.actor_id})")
        print(f"     Type: {actor.actor_type}")
        print(f"     Sophistication: {actor.sophistication}")
        print(f"     Motivation: {actor.motivation}")
    
    print("\n2. Attack Attribution:")
    attributions = profiler.attribute_attack(
        techniques=["T1190", "T1059", "T1071"],
        tools=["X-Agent"],
        target_industry="Government"
    )
    
    print(f"   Found {len(attributions)} potential threat actors:")
    for attr in attributions[:3]:
        print(f"\n   {attr['name']} ({attr['actor_id']})")
        print(f"     Confidence: {attr['confidence']:.0%}")
        print(f"     Matches: {', '.join(attr['matches'])}")
    
    print("\n3. Actor Profile:")
    profile = profiler.get_actor_profile("APT28")
    print(f"   Name: {profile['name']}")
    print(f"   Aliases: {', '.join(profile['aliases'])}")
    print(f"   Type: {profile['actor_type']}")
    print(f"   Sophistication: {profile['sophistication']}")
    print(f"   Target Industries: {', '.join(profile['target_industries'][:3])}")
    
    shutil.rmtree(temp_dir, ignore_errors=True)


def demo_risk_contextualization():
    """Demonstrate risk contextualization."""
    print_section("RISK CONTEXTUALIZATION")
    
    contextualizer = RiskContextualizer()
    
    print("1. Contextualizing CVE-2021-44228:")
    context = contextualizer.contextualize_vulnerability(
        cve_id="CVE-2021-44228",
        base_cvss_score=10.0,
        description="Remote code execution in Apache Log4j2",
        affected_systems=100000
    )
    
    print(f"   CVE ID: {context['cve_id']}")
    print(f"   Base CVSS Score: {context['base_cvss_score']}")
    print(f"   Contextualized Score: {context['contextualized_score']:.1f}")
    print(f"   Risk Multiplier: {context['risk_multiplier']:.2f}x")
    print(f"   Risk Level: {context['risk_level']}")
    
    print(f"\n   Risk Factors:")
    for factor in context['risk_factors']:
        print(f"     • {factor}")
    
    print(f"\n   MITRE ATT&CK Techniques:")
    for technique in context['mitre_techniques'][:3]:
        print(f"     • {technique['technique_id']}: {technique['name']}")
    
    print(f"\n   Recommendations:")
    for rec in context['recommendations']:
        print(f"     • {rec}")
    
    print("\n2. Threat Landscape Assessment:")
    assessment = contextualizer.assess_threat_landscape(
        industry="Government",
        country="USA"
    )
    
    print(f"   Overall Risk: {assessment['overall_risk']}")
    print(f"   Relevant Threat Actors: {len(assessment['threat_actors'])}")
    print(f"   Trending Vulnerabilities: {len(assessment['trending_vulnerabilities'])}")
    print(f"   Actively Exploited: {len(assessment['actively_exploited'])}")


def main():
    """Run all demos."""
    print("\n" + "=" * 80)
    print("  BOUNTYBOT THREAT INTELLIGENCE & VULNERABILITY ENRICHMENT DEMO")
    print("=" * 80)
    
    try:
        demo_cve_enrichment()
        demo_exploit_correlation()
        demo_threat_feeds()
        demo_mitre_mapping()
        demo_ioc_management()
        demo_vulnerability_intelligence()
        demo_threat_actor_profiling()
        demo_risk_contextualization()
        
        print("\n" + "=" * 80)
        print("  ✅ DEMO COMPLETED SUCCESSFULLY")
        print("=" * 80 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()

