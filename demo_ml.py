#!/usr/bin/env python3
"""
Demo script for BountyBot ML & Predictive Analytics Module.

Demonstrates:
- Pattern learning from historical reports
- Severity prediction
- Anomaly detection
- Researcher profiling
- False positive prediction
- Trend forecasting
"""

import sys
from datetime import datetime, timedelta
from dataclasses import dataclass
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

# Add parent directory to path
sys.path.insert(0, '.')

from bountybot.ml.feature_extractor import FeatureExtractor
from bountybot.ml.pattern_learner import PatternLearner
from bountybot.ml.severity_predictor import SeverityPredictor
from bountybot.ml.anomaly_detector import AnomalyDetector
from bountybot.ml.researcher_profiler import ResearcherProfiler
from bountybot.ml.false_positive_predictor import FalsePositivePredictor
from bountybot.ml.trend_forecaster import TrendForecaster
from bountybot.ml.model_trainer import ModelTrainer

console = Console()


@dataclass
class MockReport:
    """Mock report for demo."""
    title: str
    description: str
    vulnerability_type: str
    researcher_id: str = "researcher_1"
    submitted_at: datetime = None
    cvss_score: float = None
    
    def __post_init__(self):
        if self.submitted_at is None:
            self.submitted_at = datetime.utcnow()


@dataclass
class MockValidation:
    """Mock validation result for demo."""
    verdict: str
    confidence: float
    cvss_score: float
    severity: str
    is_duplicate: bool = False
    is_false_positive: bool = False


def create_demo_data():
    """Create demo historical data."""
    base_time = datetime.utcnow() - timedelta(days=90)
    
    reports = []
    validations = []
    timestamps = []
    
    # SQL Injection reports
    for i in range(15):
        report = MockReport(
            title=f"SQL Injection in {['Login', 'Search', 'API', 'Admin Panel'][i % 4]}",
            description=f"Found SQL injection vulnerability allowing database access. Steps:\n1. Navigate to endpoint\n2. Inject payload: ' OR '1'='1\n3. Observe unauthorized access. Impact: Full database compromise.",
            vulnerability_type="sql injection",
            researcher_id=f"researcher_{i % 3 + 1}",
            submitted_at=base_time + timedelta(days=i*2)
        )
        validation = MockValidation(
            verdict="valid",
            confidence=0.9,
            cvss_score=8.5 + (i % 3) * 0.5,
            severity="high"
        )
        reports.append(report)
        validations.append(validation)
        timestamps.append(report.submitted_at)
    
    # XSS reports
    for i in range(10):
        report = MockReport(
            title=f"XSS in {['Comments', 'Profile', 'Messages'][i % 3]}",
            description=f"Cross-site scripting vulnerability found. POC: <script>alert(document.cookie)</script>. Can steal user sessions.",
            vulnerability_type="xss",
            researcher_id=f"researcher_{i % 3 + 1}",
            submitted_at=base_time + timedelta(days=i*3 + 1)
        )
        validation = MockValidation(
            verdict="valid",
            confidence=0.85,
            cvss_score=6.5 + (i % 2) * 0.5,
            severity="medium"
        )
        reports.append(report)
        validations.append(validation)
        timestamps.append(report.submitted_at)
    
    # CSRF reports
    for i in range(5):
        report = MockReport(
            title=f"CSRF in {['Settings', 'Password Change'][i % 2]}",
            description=f"CSRF vulnerability allows unauthorized actions. Missing CSRF token validation.",
            vulnerability_type="csrf",
            researcher_id=f"researcher_{i % 2 + 1}",
            submitted_at=base_time + timedelta(days=i*5 + 2)
        )
        validation = MockValidation(
            verdict="valid",
            confidence=0.8,
            cvss_score=5.5 + (i % 2) * 0.5,
            severity="medium"
        )
        reports.append(report)
        validations.append(validation)
        timestamps.append(report.submitted_at)
    
    # False positives
    for i in range(3):
        report = MockReport(
            title="Potential vulnerability",
            description="Short report",
            vulnerability_type="unknown",
            researcher_id="researcher_4",
            submitted_at=base_time + timedelta(days=i*10 + 3)
        )
        validation = MockValidation(
            verdict="invalid",
            confidence=0.3,
            cvss_score=0.0,
            severity="none",
            is_false_positive=True
        )
        reports.append(report)
        validations.append(validation)
        timestamps.append(report.submitted_at)
    
    return reports, validations, timestamps


def demo_feature_extraction():
    """Demo feature extraction."""
    console.print("\n[bold cyan]1. FEATURE EXTRACTION[/bold cyan]")
    console.print("=" * 80)
    
    extractor = FeatureExtractor()
    
    report = MockReport(
        title="SQL Injection in Login Form",
        description="Found SQL injection vulnerability in login form. Steps to reproduce:\n1. Go to /login\n2. Enter ' OR '1'='1 in username field\n3. Observe database error revealing structure\n\nImpact: Full database access, user data compromise.\n\nPOC:\n```sql\nusername: ' OR '1'='1\npassword: anything\n```",
        vulnerability_type="sql injection"
    )
    
    features = extractor.extract_from_report(report)
    
    # Display key features
    table = Table(title="Extracted Features", box=box.ROUNDED, border_style="cyan")
    table.add_column("Feature", style="yellow")
    table.add_column("Value", style="white")
    
    key_features = [
        ('title_length', features.get('title_length')),
        ('description_length', features.get('description_length')),
        ('word_count', features.get('word_count')),
        ('has_steps', features.get('has_steps')),
        ('has_poc', features.get('has_poc')),
        ('has_impact', features.get('has_impact')),
        ('has_code_blocks', features.get('has_code_blocks')),
        ('has_sql_syntax', features.get('has_sql_syntax')),
        ('vulnerability_type', features.get('vulnerability_type')),
    ]
    
    for feature, value in key_features:
        table.add_row(feature, str(value))
    
    console.print(table)
    console.print(f"\n[green]✓[/green] Extracted {len(features)} features total")


def demo_pattern_learning(reports, validations):
    """Demo pattern learning."""
    console.print("\n[bold cyan]2. PATTERN LEARNING[/bold cyan]")
    console.print("=" * 80)
    
    learner = PatternLearner(min_frequency=2, min_confidence=0.5)
    
    patterns = learner.learn_from_reports(reports, validations)
    
    console.print(f"\n[green]✓[/green] Learned {len(patterns)} vulnerability patterns")
    
    if patterns:
        table = Table(title="Learned Patterns", box=box.ROUNDED, border_style="cyan")
        table.add_column("Vulnerability Type", style="yellow")
        table.add_column("Frequency", style="white")
        table.add_column("Confidence", style="green")
        table.add_column("Common Keywords", style="bright_black")
        
        for pattern in patterns[:5]:
            keywords = ", ".join(pattern.common_keywords[:3])
            table.add_row(
                pattern.vulnerability_type,
                str(pattern.frequency),
                f"{pattern.confidence:.2f}",
                keywords
            )
        
        console.print(table)


def demo_severity_prediction(reports, validations):
    """Demo severity prediction."""
    console.print("\n[bold cyan]3. SEVERITY PREDICTION[/bold cyan]")
    console.print("=" * 80)
    
    predictor = SeverityPredictor()
    predictor.train(reports, validations)
    
    # Predict on new report
    new_report = MockReport(
        title="SQL Injection in Admin Panel",
        description="Critical SQL injection allowing full database access with admin privileges. Detailed POC included with exploitation steps.",
        vulnerability_type="sql injection"
    )
    
    prediction = predictor.predict(new_report)
    
    console.print(f"\n[bold]New Report:[/bold] {new_report.title}")
    console.print(f"[bold]Predicted CVSS:[/bold] {prediction.predicted_value['cvss_score']:.1f}")
    console.print(f"[bold]Predicted Severity:[/bold] {prediction.predicted_value['severity'].upper()}")
    console.print(f"[bold]Confidence:[/bold] {prediction.confidence:.1%}")
    console.print(f"\n[bright_black]{prediction.reasoning}[/bright_black]")
    
    # Show probability distribution
    table = Table(title="Severity Probability Distribution", box=box.ROUNDED, border_style="cyan")
    table.add_column("Severity", style="yellow")
    table.add_column("Probability", style="white")
    
    for severity, prob in prediction.probability_distribution.items():
        table.add_row(severity.capitalize(), f"{prob:.1%}")
    
    console.print(table)


def demo_anomaly_detection(reports):
    """Demo anomaly detection."""
    console.print("\n[bold cyan]4. ANOMALY DETECTION[/bold cyan]")
    console.print("=" * 80)
    
    detector = AnomalyDetector(sensitivity=2.0)
    detector.build_baseline(reports)
    
    # Test normal report
    normal_report = MockReport(
        title="SQL Injection in Search Function",
        description="Found SQL injection in search. Steps to reproduce with detailed POC and impact analysis. " * 5,
        vulnerability_type="sql injection"
    )
    
    normal_result = detector.detect_anomalies(normal_report)
    
    console.print(f"\n[bold]Normal Report Analysis:[/bold]")
    console.print(f"Anomaly Score: {normal_result.anomaly_score:.2f}")
    console.print(f"Is Anomaly: {normal_result.is_anomaly}")
    
    # Test anomalous report
    anomalous_report = MockReport(
        title="Bug",
        description="Found issue",
        vulnerability_type="unknown"
    )
    
    anomaly_result = detector.detect_anomalies(anomalous_report)
    
    console.print(f"\n[bold]Anomalous Report Analysis:[/bold]")
    console.print(f"Anomaly Score: [red]{anomaly_result.anomaly_score:.2f}[/red]")
    console.print(f"Is Anomaly: [red]{anomaly_result.is_anomaly}[/red]")
    console.print(f"Type: {anomaly_result.anomaly_type.value if anomaly_result.anomaly_type else 'None'}")
    console.print(f"\n[bright_black]{anomaly_result.explanation}[/bright_black]")


def demo_researcher_profiling(reports, validations):
    """Demo researcher profiling."""
    console.print("\n[bold cyan]5. RESEARCHER PROFILING[/bold cyan]")
    console.print("=" * 80)
    
    profiler = ResearcherProfiler()
    
    # Build profiles for each researcher
    researcher_ids = set(r.researcher_id for r in reports)
    
    for researcher_id in list(researcher_ids)[:3]:
        researcher_reports = [r for r in reports if r.researcher_id == researcher_id]
        researcher_validations = [
            validations[i] for i, r in enumerate(reports)
            if r.researcher_id == researcher_id
        ]
        
        profile = profiler.build_profile(researcher_id, researcher_reports, researcher_validations)
        
        panel_content = f"""
[bold]Total Submissions:[/bold] {profile.total_submissions}
[bold]Valid Submissions:[/bold] {profile.valid_submissions}
[bold]Average Severity:[/bold] {profile.average_severity:.1f}
[bold]False Positive Rate:[/bold] {profile.false_positive_rate:.1%}
[bold]Reputation Score:[/bold] {profile.reputation_score:.1f}/100
[bold]Trust Level:[/bold] {profile.trust_level.upper()}
[bold]Specializations:[/bold] {', '.join(profile.specializations) if profile.specializations else 'None'}
        """
        
        console.print(Panel(panel_content, title=f"[cyan]{researcher_id}[/cyan]", border_style="cyan"))


def demo_false_positive_prediction(reports, validations):
    """Demo false positive prediction."""
    console.print("\n[bold cyan]6. FALSE POSITIVE PREDICTION[/bold cyan]")
    console.print("=" * 80)
    
    predictor = FalsePositivePredictor(threshold=0.7)
    predictor.train(reports, validations)
    
    stats = predictor.get_training_stats()
    console.print(f"\n[bold]Training Stats:[/bold]")
    console.print(f"Total Samples: {stats['total_samples']}")
    console.print(f"False Positives: {stats['false_positives']}")
    console.print(f"FP Rate: {stats['fp_rate']:.1%}")
    
    # Predict on high-quality report
    good_report = MockReport(
        title="Critical SQL Injection with Full POC",
        description="Comprehensive SQL injection report with detailed steps, POC, impact analysis, and remediation recommendations. " * 10,
        vulnerability_type="sql injection"
    )
    
    good_prediction = predictor.predict(good_report)
    
    console.print(f"\n[bold]High-Quality Report:[/bold]")
    console.print(f"FP Probability: [green]{good_prediction.probability_distribution['false_positive']:.1%}[/green]")
    console.print(f"Predicted: {'FALSE POSITIVE' if good_prediction.predicted_value else 'LEGITIMATE'}")
    
    # Predict on low-quality report
    bad_report = MockReport(
        title="Bug found",
        description="Issue",
        vulnerability_type="unknown"
    )
    
    bad_prediction = predictor.predict(bad_report)
    
    console.print(f"\n[bold]Low-Quality Report:[/bold]")
    console.print(f"FP Probability: [red]{bad_prediction.probability_distribution['false_positive']:.1%}[/red]")
    console.print(f"Predicted: {'FALSE POSITIVE' if bad_prediction.predicted_value else 'LEGITIMATE'}")


def demo_trend_forecasting(reports, timestamps):
    """Demo trend forecasting."""
    console.print("\n[bold cyan]7. TREND FORECASTING[/bold cyan]")
    console.print("=" * 80)
    
    forecaster = TrendForecaster(forecast_days=30)
    forecaster.analyze_historical_data(reports, timestamps)
    
    # Volume forecast
    volume_forecast = forecaster.forecast_volume(days_ahead=30)
    
    console.print(f"\n[bold]Volume Forecast (30 days):[/bold]")
    console.print(f"Current Daily Average: {volume_forecast['daily_average']:.1f} reports/day")
    console.print(f"Growth Rate: {volume_forecast['growth_rate']:.2%}")
    console.print(f"Total Forecasted: {volume_forecast['total_forecasted']:.0f} reports")
    console.print(f"Confidence: {volume_forecast['confidence']:.1%}")
    
    # Type forecast
    type_forecast = forecaster.forecast_vulnerability_types(days_ahead=30)
    
    if type_forecast.get('emerging_threats'):
        console.print(f"\n[bold red]Emerging Threats:[/bold red] {', '.join(type_forecast['emerging_threats'])}")
    
    # Seasonal patterns
    seasonal = forecaster.identify_seasonal_patterns()
    
    if 'day_of_week_pattern' in seasonal:
        console.print(f"\n[bold]Seasonal Patterns:[/bold]")
        console.print(f"Busiest Day: {seasonal['day_of_week_pattern']['busiest_day']}")
        console.print(f"Busiest Hour: {seasonal['hourly_pattern']['busiest_hour']}:00")


def main():
    """Run ML demo."""
    console.print(Panel.fit(
        "[bold cyan]BountyBot ML & Predictive Analytics Demo[/bold cyan]\n"
        "Machine Learning for Vulnerability Intelligence",
        border_style="cyan"
    ))
    
    # Create demo data
    console.print("\n[yellow]Creating demo historical data...[/yellow]")
    reports, validations, timestamps = create_demo_data()
    console.print(f"[green]✓[/green] Created {len(reports)} historical reports")
    
    # Run demos
    demo_feature_extraction()
    demo_pattern_learning(reports, validations)
    demo_severity_prediction(reports, validations)
    demo_anomaly_detection(reports)
    demo_researcher_profiling(reports, validations)
    demo_false_positive_prediction(reports, validations)
    demo_trend_forecasting(reports, timestamps)
    
    # Summary
    console.print("\n" + "=" * 80)
    console.print(Panel.fit(
        "[bold green]✓ ML Demo Complete![/bold green]\n\n"
        "Demonstrated:\n"
        "• Feature extraction from vulnerability reports\n"
        "• Pattern learning and matching\n"
        "• ML-based severity prediction\n"
        "• Anomaly detection for novel attacks\n"
        "• Researcher profiling and reputation\n"
        "• False positive prediction\n"
        "• Trend forecasting and seasonal analysis",
        border_style="green"
    ))


if __name__ == "__main__":
    main()

