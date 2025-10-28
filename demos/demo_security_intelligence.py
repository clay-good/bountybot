#!/usr/bin/env python3
"""
BountyBot v2.10.0 - Advanced Security Intelligence System Demo

Demonstrates real-time threat correlation, exploit prediction,
automated threat hunting, and comprehensive enrichment pipeline.
"""

import asyncio
from datetime import datetime, timedelta
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from bountybot.threat_intel import (
    ThreatCorrelationEngine,
    ExploitPredictor,
    ThreatHunter,
    ThreatIntelligenceEnrichmentPipeline,
    CVEData,
    ExploitData,
    ThreatActor,
    IoC,
    IoCType,
    MitreAttackTechnique,
    ExploitMaturity
)

console = Console()


async def demo_threat_correlation():
    """Demonstrate real-time threat correlation."""
    console.print("\n[bold cyan]═══ 1. Real-Time Threat Correlation ═══[/bold cyan]\n")
    
    engine = ThreatCorrelationEngine()
    
    # Create sample threat intelligence data
    cve = CVEData(
        cve_id="CVE-2024-1234",
        description="Critical SQL Injection vulnerability in web application",
        published_date=datetime.utcnow() - timedelta(days=5),
        last_modified_date=datetime.utcnow(),
        cvss_v3_score=9.8,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    
    exploit = ExploitData(
        exploit_id="EXP-2024-001",
        title="SQL Injection Exploit for CVE-2024-1234",
        description="Weaponized exploit with automated data exfiltration",
        maturity=ExploitMaturity.HIGH,
        verified=True,
        cve_ids=["CVE-2024-1234"]
    )
    
    actor = ThreatActor(
        actor_id="apt28",
        name="APT28 (Fancy Bear)",
        actor_type="nation-state",
        sophistication="advanced",
        motivation="espionage"
    )
    
    ioc = IoC(
        ioc_id="ioc-001",
        value="malicious-domain.com",
        ioc_type=IoCType.DOMAIN,
        confidence=0.95,
        first_seen=datetime.utcnow() - timedelta(days=2),
        last_seen=datetime.utcnow()
    )
    
    mitre = MitreAttackTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        description="Adversaries may attempt to exploit a weakness in an Internet-facing computer or program"
    )
    
    # Perform correlation
    console.print("[yellow]⚙️  Correlating threat intelligence from multiple sources...[/yellow]")
    correlation = await engine.correlate(
        vulnerability_id="vuln-2024-001",
        vulnerability_type="SQL Injection",
        cves=[cve],
        exploits=[exploit],
        threat_actors=[actor],
        iocs=[ioc],
        mitre_techniques=[mitre]
    )
    
    # Display results
    table = Table(title="Threat Correlation Results", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Vulnerability ID", correlation.vulnerability_id)
    table.add_row("Vulnerability Type", correlation.vulnerability_type)
    table.add_row("Correlation Strength", f"[bold]{correlation.correlation_strength.value.upper()}[/bold]")
    table.add_row("Correlation Score", f"{correlation.correlation_score:.2f}")
    table.add_row("Threat Severity", f"[red]{correlation.threat_severity.value.upper()}[/red]")
    table.add_row("CVEs Found", str(len(correlation.cves)))
    table.add_row("Exploits Found", str(len(correlation.exploits)))
    table.add_row("Threat Actors", str(len(correlation.threat_actors)))
    table.add_row("IOCs", str(len(correlation.iocs)))
    table.add_row("MITRE Techniques", str(len(correlation.mitre_techniques)))
    table.add_row("Exploit Maturity", correlation.exploit_maturity.value)
    table.add_row("Weaponized", "✅ YES" if correlation.weaponized else "❌ NO")
    table.add_row("APT Associated", "✅ YES" if correlation.apt_associated else "❌ NO")
    
    console.print(table)
    
    # Display recommendations
    console.print("\n[bold yellow]📋 Recommended Actions:[/bold yellow]")
    for i, action in enumerate(correlation.recommended_actions[:5], 1):
        console.print(f"  {i}. {action}")


async def demo_exploit_prediction():
    """Demonstrate ML-based exploit prediction."""
    console.print("\n[bold cyan]═══ 2. ML-Based Exploit Prediction ═══[/bold cyan]\n")
    
    predictor = ExploitPredictor()
    
    # Predict for high-risk RCE vulnerability
    console.print("[yellow]⚙️  Predicting exploit likelihood for RCE vulnerability...[/yellow]")
    prediction = await predictor.predict(
        vulnerability_id="vuln-2024-002",
        vulnerability_type="Remote Code Execution",
        cvss_score=9.8,
        public_disclosure=True,
        proof_of_concept_available=True,
        vendor_patch_available=False,
        attack_vector="Network",
        privileges_required="None",
        user_interaction="None",
        affected_products=["Apache Struts", "Spring Framework"]
    )
    
    # Display results
    table = Table(title="Exploit Prediction Results", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Vulnerability ID", prediction.vulnerability_id)
    table.add_row("Vulnerability Type", prediction.vulnerability_type)
    table.add_row("Exploit Likelihood", f"[bold red]{prediction.exploit_likelihood.value.upper()}[/bold red]")
    table.add_row("Exploit Probability", f"{prediction.exploit_probability:.1%}")
    table.add_row("Technical Complexity", f"{prediction.technical_complexity_score:.2f} (lower = easier)")
    table.add_row("Exploit Value", f"{prediction.exploit_value_score:.2f}")
    table.add_row("Attacker Interest", f"{prediction.attacker_interest_score:.2f}")
    table.add_row("Defense Difficulty", f"{prediction.defense_difficulty_score:.2f}")
    table.add_row("Weaponization Timeline", f"{prediction.predicted_weaponization_days} days")
    table.add_row("Exploitation Timeline", f"{prediction.predicted_exploitation_days} days")
    table.add_row("Priority Level", f"[red]{prediction.priority_level.upper()}[/red]")
    table.add_row("Mitigation Urgency", prediction.mitigation_urgency)
    
    console.print(table)
    
    # Display risk factors
    console.print("\n[bold red]⚠️  Risk Factors:[/bold red]")
    for i, factor in enumerate(prediction.risk_factors[:5], 1):
        console.print(f"  {i}. {factor}")
    
    # Display protective factors
    if prediction.protective_factors:
        console.print("\n[bold green]🛡️  Protective Factors:[/bold green]")
        for i, factor in enumerate(prediction.protective_factors[:3], 1):
            console.print(f"  {i}. {factor}")


async def demo_threat_hunting():
    """Demonstrate automated threat hunting."""
    console.print("\n[bold cyan]═══ 3. Automated Threat Hunting ═══[/bold cyan]\n")
    
    hunter = ThreatHunter()
    
    # Create hunt from template
    console.print("[yellow]⚙️  Creating APT activity hunt from template...[/yellow]")
    hunt = await hunter.create_hunt_from_template("apt_activity")
    
    console.print(f"[green]✅ Hunt created: {hunt.hunt_name}[/green]")
    console.print(f"   Priority: {hunt.priority.value.upper()}")
    console.print(f"   Type: {hunt.hunt_type}")
    
    # Execute hunt
    console.print("\n[yellow]⚙️  Executing threat hunt...[/yellow]")
    result = await hunter.execute_hunt(hunt.hunt_id)
    
    # Display results
    table = Table(title="Threat Hunt Results", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Hunt ID", result.hunt_id)
    table.add_row("Hunt Name", result.hunt_name)
    table.add_row("Status", f"[bold]{result.status.value.upper()}[/bold]")
    table.add_row("Priority", result.priority.value.upper())
    table.add_row("Findings", str(len(result.findings)))
    table.add_row("Indicators Found", str(len(result.indicators_found)))
    table.add_row("Confidence Score", f"{result.confidence_score:.1%}")
    table.add_row("Started", result.started_at.strftime("%Y-%m-%d %H:%M:%S") if result.started_at else "N/A")
    table.add_row("Completed", result.completed_at.strftime("%Y-%m-%d %H:%M:%S") if result.completed_at else "N/A")
    
    console.print(table)
    
    if result.findings:
        console.print("\n[bold yellow]🔍 Hunt Findings:[/bold yellow]")
        for i, finding in enumerate(result.findings[:3], 1):
            console.print(f"  {i}. {finding}")


async def demo_enrichment_pipeline():
    """Demonstrate comprehensive enrichment pipeline."""
    console.print("\n[bold cyan]═══ 4. Comprehensive Enrichment Pipeline ═══[/bold cyan]\n")
    
    pipeline = ThreatIntelligenceEnrichmentPipeline()
    
    # Enrich validation with full threat intelligence
    console.print("[yellow]⚙️  Enriching validation with threat intelligence...[/yellow]")
    enriched = await pipeline.enrich_with_auto_hunt(
        validation_id="val-2024-001",
        vulnerability_type="SQL Injection",
        severity="critical",
        cve_ids=["CVE-2024-1234"],
        cvss_score=9.8,
        attack_vector="Network",
        privileges_required="None",
        user_interaction="None",
        public_disclosure=True,
        vendor_patch_available=False,
        affected_products=["WordPress", "Drupal"]
    )
    
    # Display results
    table = Table(title="Enriched Validation Results", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Validation ID", enriched.validation_id)
    table.add_row("Vulnerability Type", enriched.vulnerability_type)
    table.add_row("Severity", enriched.severity.upper())
    table.add_row("Risk Level", f"[red]{enriched.risk_level.upper()}[/red]")
    table.add_row("Overall Risk Score", f"{enriched.overall_risk_score:.2f}")
    table.add_row("Priority Score", f"{enriched.priority_score:.2f}")
    table.add_row("Mitigation Timeline", enriched.mitigation_timeline)
    table.add_row("Enrichment Sources", ", ".join(enriched.enrichment_sources))
    table.add_row("Threat Hunts", str(len(enriched.threat_hunts)))
    
    console.print(table)

    # Display recommended actions
    console.print("\n[bold yellow]💡 Recommended Actions:[/bold yellow]")
    for i, action in enumerate(enriched.recommended_actions[:5], 1):
        console.print(f"  {i}. {action}")


async def main():
    """Run all demos."""
    console.print(Panel.fit(
        "[bold white]BountyBot v2.10.0 - Advanced Security Intelligence System[/bold white]\n"
        "[cyan]Real-time threat correlation, exploit prediction, and automated threat hunting[/cyan]",
        border_style="blue"
    ))
    
    try:
        await demo_threat_correlation()
        await demo_exploit_prediction()
        await demo_threat_hunting()
        await demo_enrichment_pipeline()
        
        console.print("\n" + "═" * 80)
        console.print("[bold green]✅ All demos completed successfully![/bold green]")
        console.print("\n[bold cyan]Key Features Demonstrated:[/bold cyan]")
        console.print("  • Real-time threat correlation with multi-source intelligence")
        console.print("  • ML-based exploit prediction with weaponization timelines")
        console.print("  • Automated threat hunting with predefined templates")
        console.print("  • Comprehensive enrichment pipeline with actionable intelligence")
        console.print("\n[bold yellow]BountyBot v2.10.0: Enterprise-grade security intelligence for bug bounty validation[/bold yellow]")
        
    except Exception as e:
        console.print(f"\n[bold red]❌ Error: {e}[/bold red]")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
