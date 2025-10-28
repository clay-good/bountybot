import logging
import time
from pathlib import Path
from typing import Dict, Any, Optional, List

from bountybot.config_loader import ConfigLoader
from bountybot.models import Report, ValidationResult
from bountybot.parsers import JSONParser, MarkdownParser, TextParser
from bountybot.parsers.html_parser import BountyHTMLParser
from bountybot.ai_providers import AnthropicProvider, OPENAI_AVAILABLE, GEMINI_AVAILABLE
if OPENAI_AVAILABLE:
    from bountybot.ai_providers import OpenAIProvider
if GEMINI_AVAILABLE:
    from bountybot.ai_providers import GeminiProvider
from bountybot.validators import AIValidator, CodeAnalyzer
from bountybot.validators.report_validator import ReportValidator
from bountybot.validators.poc_executor import PoCExecutor
from bountybot.outputs import JSONOutput, MarkdownOutput
from bountybot.outputs.html_output import HTMLOutput
from bountybot.extractors import HTTPRequestExtractor
from bountybot.generators import PoCGenerator
from bountybot.scoring import CVSSCalculator
from bountybot.deduplication import DuplicateDetector
from bountybot.logging import StructuredLogger, PerformanceTracker
from bountybot.analysis import (
    FalsePositiveDetector,
    ExploitComplexityAnalyzer,
    AttackChainDetector
)
from bountybot.prioritization import PriorityEngine
from bountybot.scanners import DynamicScanner
from bountybot.integrations import IntegrationManager
from bountybot.remediation import RemediationEngine
from bountybot.researcher_reputation import ReputationManager
from bountybot.bounty_payout import PayoutEngine
from bountybot.report_clustering import ReportClusteringEngine, SemanticSimilarityAnalyzer
from bountybot.communication import ResponseGenerator

logger = logging.getLogger(__name__)
structured_logger = StructuredLogger(__name__)


class Orchestrator:
    """
    Main orchestrator that coordinates the entire validation workflow.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize orchestrator with configuration.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        
        # Initialize AI provider
        provider_name = config['api']['default_provider']
        provider_config = config['api']['providers'][provider_name]

        if provider_name == 'anthropic':
            self.ai_provider = AnthropicProvider(provider_config)
        elif provider_name == 'openai':
            if not OPENAI_AVAILABLE:
                raise ImportError("OpenAI provider requested but openai package not installed. Install with: pip install openai")
            self.ai_provider = OpenAIProvider(provider_config)
        elif provider_name == 'gemini':
            if not GEMINI_AVAILABLE:
                raise ImportError("Gemini provider requested but google-generativeai package not installed. Install with: pip install google-generativeai")
            self.ai_provider = GeminiProvider(provider_config)
        else:
            raise ValueError(f"Unsupported AI provider: {provider_name}. Supported: anthropic, openai, gemini")
        
        # Initialize validators
        self.ai_validator = AIValidator(self.ai_provider)
        self.code_analyzer = CodeAnalyzer(config.get('code_analysis', {}))
        self.report_validator = ReportValidator()
        self.poc_executor = PoCExecutor(config.get('poc_execution', {}))

        # Initialize extractors and generators
        self.http_extractor = HTTPRequestExtractor()
        self.poc_generator = PoCGenerator(self.ai_provider)

        # Initialize advanced features
        self.cvss_calculator = CVSSCalculator()
        self.duplicate_detector = DuplicateDetector(config.get('deduplication', {}))
        self.fp_detector = FalsePositiveDetector(config.get('false_positive_detection', {}))
        self.complexity_analyzer = ExploitComplexityAnalyzer(config.get('exploit_complexity', {}))
        self.chain_detector = AttackChainDetector(config.get('attack_chains', {}))
        self.priority_engine = PriorityEngine(config.get('prioritization', {}))

        # Initialize dynamic scanner
        self.dynamic_scanner = DynamicScanner(config.get('dynamic_scanning', {}))

        # Initialize integration manager
        self.integration_manager = IntegrationManager(config)

        # Initialize remediation engine
        self.remediation_engine = RemediationEngine(self.ai_provider)

        # Initialize reputation manager
        self.reputation_manager = ReputationManager()

        # Initialize bounty payout engine
        self.payout_engine = PayoutEngine(config.get('bounty_payout', {}))

        # Initialize report clustering engine
        self.clustering_engine = ReportClusteringEngine()
        self.similarity_analyzer = SemanticSimilarityAnalyzer()

        # Initialize communication assistant
        self.response_generator = ResponseGenerator()

        logger.info("Orchestrator initialized with advanced features (CVSS, dedup, FP detection, complexity, chains, prioritization, dynamic scanning, integrations, remediation, reputation, payout, clustering, communication)")
    
    def validate_report(self,
                       report_path: str,
                       codebase_path: Optional[str] = None,
                       target_url: Optional[str] = None) -> ValidationResult:
        """
        Validate a bug bounty report with advanced features.

        Args:
            report_path: Path to bug bounty report file
            codebase_path: Optional path to codebase for static analysis
            target_url: Optional target URL for dynamic testing

        Returns:
            Validation result with CVSS scoring, duplicate detection, and metrics
        """
        start_time = time.time()
        stage_timings = {}

        # Set up request tracking
        request_id = structured_logger.set_request_id()
        structured_logger.info("Starting validation", report_path=report_path)

        try:
            # Step 1: Parse report
            with PerformanceTracker("parse_report", structured_logger) as tracker:
                logger.info(f"Parsing report: {report_path}")
                report = self._parse_report(report_path)
                logger.info(f"Successfully parsed report: {report.title}")
                stage_timings['parse_report'] = time.time() - start_time

            # Step 1.5: Pre-validate report quality
            is_valid, errors, warnings = self.report_validator.validate(report)
            if errors:
                logger.warning(f"Report has {len(errors)} validation errors")
                for error in errors:
                    logger.warning(f"  - {error}")
            if warnings:
                logger.info(f"Report has {len(warnings)} quality warnings")

            quality_score = self.report_validator.get_quality_score(report)
            logger.info(f"Report quality score: {quality_score}/100")

            # Step 2: Extract HTTP requests
            logger.info("Extracting HTTP requests from report")
            http_requests = self.http_extractor.extract_from_report(report)

            if http_requests:
                logger.info(f"Extracted {len(http_requests)} HTTP request(s)")

                # Validate extracted requests
                http_validation_issues = []
                for i, req in enumerate(http_requests, 1):
                    is_valid, issues = self.http_extractor.validate_request(req)
                    if issues:
                        logger.warning(f"HTTP request {i} has validation issues: {issues}")
                        http_validation_issues.extend([f"Request {i}: {issue}" for issue in issues])
                    else:
                        logger.info(f"HTTP request {i} validated successfully")
            else:
                logger.info("No HTTP requests extracted from report")
                http_validation_issues = []

            # Step 3: Code analysis (MANDATORY for payout decisions)
            code_analysis = None
            if not codebase_path:
                # Code analysis is now MANDATORY for payout decisions
                logger.warning("No codebase path provided - validation will proceed but payout will be blocked")
                result.recommendations_security_team.append(
                    "⚠️ CRITICAL: Codebase analysis is required before approving any payout"
                )
            elif self.config.get('code_analysis', {}).get('enabled', True):
                stage_start = time.time()
                logger.info(f"Analyzing codebase: {codebase_path}")
                code_analysis = self.code_analyzer.analyze(
                    codebase_path,
                    vulnerability_type=report.vulnerability_type,
                    affected_files=report.affected_components
                )
                logger.info(f"Code analysis complete: {len(code_analysis.vulnerable_patterns)} patterns found")
                stage_timings['code_analysis'] = time.time() - stage_start

            # Step 4: Dynamic testing (if target provided)
            dynamic_test = None
            if target_url and self.config.get('dynamic_scanning', {}).get('enabled', False):
                stage_start = time.time()
                logger.info(f"Running dynamic security scan on: {target_url}")
                try:
                    # Determine scan types based on vulnerability type
                    scan_types = self._get_scan_types_for_vulnerability(report.vulnerability_type)
                    dynamic_test = self.dynamic_scanner.scan(target_url, scan_types)

                    if dynamic_test.findings:
                        logger.info(f"Dynamic scan found {len(dynamic_test.findings)} issues")
                        for finding in dynamic_test.findings:
                            logger.info(f"  - {finding.vulnerability_type} ({finding.severity.value})")
                    else:
                        logger.info("Dynamic scan completed with no findings")

                    structured_logger.info(
                        "Dynamic scan completed",
                        findings_count=len(dynamic_test.findings),
                        requests_sent=dynamic_test.requests_sent,
                        duration=dynamic_test.scan_duration
                    )
                except Exception as e:
                    logger.error(f"Dynamic scanning failed: {e}")
                    structured_logger.error("Dynamic scan error", error=str(e))
                stage_timings['dynamic_scan'] = time.time() - stage_start

            # Step 5: AI validation
            logger.info("Running AI validation")
            result = self.ai_validator.validate(report, code_analysis, dynamic_test)
            logger.info(f"AI validation complete: {result.verdict.value} ({result.confidence}% confidence)")

            # Add dynamic test results to validation result
            if dynamic_test:
                result.dynamic_test = dynamic_test

            # Step 6: Add extracted HTTP requests to result
            result.extracted_http_requests = http_requests
            result.http_validation_issues = http_validation_issues

            # Step 7: Generate and Execute PoC if vulnerability is valid
            if result.verdict.value == 'VALID' and http_requests:
                stage_start = time.time()
                logger.info("Generating proof-of-concept exploit")
                try:
                    poc = self.poc_generator.generate(report, http_requests, result)
                    result.generated_poc = poc
                    logger.info("PoC generated successfully")

                    # Add PoC to recommendations
                    result.recommendations_security_team.insert(0,
                        "Review the generated proof-of-concept exploit for testing")
                except Exception as e:
                    logger.error(f"Failed to generate PoC: {e}")
                stage_timings['generate_poc'] = time.time() - stage_start

                # Step 7b: Execute PoC to verify vulnerability (if target URL provided)
                if target_url and result.generated_poc and self.config.get('poc_execution', {}).get('enabled', False):
                    stage_start = time.time()
                    logger.info("Executing PoC to verify vulnerability")
                    try:
                        import asyncio
                        # Run async PoC execution
                        loop = asyncio.get_event_loop()
                        if loop.is_running():
                            # If loop is already running, create a task
                            execution_result = None
                            logger.warning("Event loop already running, skipping PoC execution")
                        else:
                            execution_result = loop.run_until_complete(
                                self.poc_executor.execute_poc(
                                    poc=result.generated_poc,
                                    target_url=target_url,
                                    vulnerability_type=report.vulnerability_type
                                )
                            )

                        if execution_result:
                            result.poc_execution_result = execution_result

                            if execution_result.vulnerability_confirmed:
                                logger.info(f"✅ PoC execution CONFIRMED vulnerability (confidence: {execution_result.confidence:.2%})")
                                result.recommendations_security_team.insert(0,
                                    f"✅ VERIFIED: PoC successfully exploited vulnerability with {execution_result.confidence:.0%} confidence"
                                )
                                # Increase overall confidence since we have proof
                                result.confidence = min(result.confidence + 10, 100)
                            else:
                                logger.warning(f"❌ PoC execution FAILED to confirm vulnerability")
                                result.recommendations_security_team.insert(0,
                                    "⚠️ WARNING: Generated PoC failed to exploit vulnerability - may be false positive or protected by controls"
                                )
                                # Decrease confidence since PoC didn't work
                                result.confidence = max(result.confidence - 15, 0)
                    except Exception as e:
                        logger.error(f"Failed to execute PoC: {e}")
                    stage_timings['poc_execution'] = time.time() - stage_start

            # Step 8: Calculate CVSS score
            stage_start = time.time()
            logger.info("Calculating CVSS score")
            try:
                cvss_score = self.cvss_calculator.calculate_from_report(report, result)
                result.cvss_score = cvss_score
                logger.info(f"CVSS Score: {cvss_score.base_score} ({cvss_score.severity_rating})")
                structured_logger.info(
                    "CVSS score calculated",
                    base_score=cvss_score.base_score,
                    severity=cvss_score.severity_rating,
                    vector=cvss_score.vector_string
                )
            except Exception as e:
                logger.error(f"Failed to calculate CVSS score: {e}")
            stage_timings['cvss_calculation'] = time.time() - stage_start

            # Step 9: Check for duplicates
            stage_start = time.time()
            logger.info("Checking for duplicate reports")
            try:
                duplicate_match = self.duplicate_detector.check_duplicate(report)
                result.duplicate_check = duplicate_match
                if duplicate_match.is_duplicate:
                    logger.warning(
                        f"Potential duplicate detected: {duplicate_match.confidence:.2%} confidence"
                    )
                    structured_logger.security_event(
                        "duplicate_detected",
                        {
                            "confidence": duplicate_match.confidence,
                            "matched_report": duplicate_match.matched_report_id,
                        },
                        severity="WARNING"
                    )
                else:
                    logger.info("No duplicate detected")
                    # Add this report to duplicate detection database
                    self.duplicate_detector.add_report(report)
            except Exception as e:
                logger.error(f"Failed to check duplicates: {e}")
            stage_timings['duplicate_check'] = time.time() - stage_start

            # Step 10: False Positive Detection
            stage_start = time.time()
            logger.info("Analyzing for false positive indicators")
            try:
                fp_indicators = self.fp_detector.analyze(report, result)
                result.false_positive_indicators = [ind['description'] for ind in fp_indicators.indicators]

                if fp_indicators.is_likely_false_positive:
                    logger.warning(
                        f"Likely false positive detected: {fp_indicators.confidence:.1f}% confidence"
                    )
                    structured_logger.security_event(
                        "false_positive_detected",
                        {
                            "confidence": fp_indicators.confidence,
                            "risk_score": fp_indicators.risk_score,
                            "indicator_count": len(fp_indicators.indicators),
                        },
                        severity="WARNING"
                    )
                    # Add to recommendations
                    result.recommendations_security_team.append(
                        f"⚠️  False positive likelihood: {fp_indicators.confidence:.1f}% - {fp_indicators.reasoning}"
                    )
                else:
                    logger.info(f"False positive analysis: {fp_indicators.confidence:.1f}% FP confidence, {fp_indicators.risk_score:.1f} risk score")
            except Exception as e:
                logger.error(f"Failed to analyze false positives: {e}")
            stage_timings['false_positive_detection'] = time.time() - stage_start

            # Step 11: Exploit Complexity Analysis
            stage_start = time.time()
            logger.info("Analyzing exploit complexity")
            try:
                complexity_score = self.complexity_analyzer.analyze(report, result, result.cvss_score)
                result.exploit_complexity_score = complexity_score.overall_score

                logger.info(
                    f"Exploit Complexity: {complexity_score.overall_score:.1f}/100 "
                    f"(skill: {complexity_score.skill_level.value}, time: {complexity_score.time_to_exploit.value})"
                )

                # Add to recommendations
                if complexity_score.overall_score >= 70:
                    result.recommendations_security_team.append(
                        f"⚡ High exploitability: {complexity_score.overall_score:.0f}/100 - "
                        f"Can be exploited by {complexity_score.skill_level.value.replace('_', ' ')} in {complexity_score.time_to_exploit.value}"
                    )
                elif complexity_score.overall_score <= 30:
                    result.recommendations_security_team.append(
                        f"🛡️  Low exploitability: {complexity_score.overall_score:.0f}/100 - "
                        f"Requires {complexity_score.skill_level.value.replace('_', ' ')} skill and {complexity_score.time_to_exploit.value} to exploit"
                    )

                # Add barriers to recommendations
                if complexity_score.barriers:
                    result.recommendations_researcher.append(
                        f"Exploitation barriers: {', '.join(complexity_score.barriers[:3])}"
                    )
            except Exception as e:
                logger.error(f"Failed to analyze exploit complexity: {e}")
            stage_timings['exploit_complexity'] = time.time() - stage_start

            # Step 12: Attack Chain Detection
            stage_start = time.time()
            logger.info("Detecting attack chains")
            try:
                attack_chain = self.chain_detector.detect(report, result)

                if attack_chain.is_chain:
                    logger.info(
                        f"Attack chain detected: {attack_chain.chain_length} vulnerabilities, "
                        f"type: {attack_chain.chain_type.value if attack_chain.chain_type else 'unknown'}, "
                        f"impact multiplier: {attack_chain.impact_multiplier:.1f}x"
                    )

                    # Add to recommendations
                    result.recommendations_security_team.insert(0,
                        f"🔗 Attack Chain: {attack_chain.combined_impact} "
                        f"(impact multiplier: {attack_chain.impact_multiplier:.1f}x)"
                    )

                    # Add exploitation path
                    if attack_chain.exploitation_path:
                        result.recommendations_security_team.append(
                            f"Exploitation path: {' → '.join(attack_chain.exploitation_path[:3])}"
                        )

                    structured_logger.security_event(
                        "attack_chain_detected",
                        {
                            "chain_length": attack_chain.chain_length,
                            "chain_type": attack_chain.chain_type.value if attack_chain.chain_type else None,
                            "impact_multiplier": attack_chain.impact_multiplier,
                        },
                        severity="INFO"
                    )
                else:
                    logger.info("No attack chain detected")
            except Exception as e:
                logger.error(f"Failed to detect attack chains: {e}")
            stage_timings['attack_chain_detection'] = time.time() - stage_start

            # Step 13: Calculate Priority Score
            stage_start = time.time()
            try:
                logger.info("Calculating remediation priority...")
                priority_score = self.priority_engine.calculate_priority(result)
                result.priority_score = priority_score

                logger.info(
                    f"Priority calculated: {priority_score.priority_level.value.upper()} "
                    f"(score: {priority_score.overall_score:.1f}/100, SLA: {priority_score.recommended_sla})"
                )

                # Add priority to recommendations
                result.recommendations_security_team.insert(0,
                    f"PRIORITY: {priority_score.priority_level.value.upper()} "
                    f"(Score: {priority_score.overall_score:.1f}/100) - {priority_score.recommended_sla}"
                )

                if priority_score.escalation_required:
                    result.recommendations_security_team.insert(1,
                        "⚠️ ESCALATION REQUIRED: High-priority issue requiring immediate attention"
                    )
                    structured_logger.security_event(
                        event_type="escalation_required",
                        details={
                            "report_title": report.title,
                            "priority_score": priority_score.overall_score,
                            "priority_level": priority_score.priority_level.value,
                            "risk_factors": priority_score.risk_factors
                        },
                        severity="CRITICAL"
                    )

            except Exception as e:
                logger.error(f"Failed to calculate priority: {e}")
            stage_timings['priority_calculation'] = time.time() - stage_start

            # Add performance metrics
            result.stage_timings = stage_timings
            result.processing_time_seconds = time.time() - start_time
            result.total_cost = self.ai_provider.total_cost
            result.request_id = request_id

            # Get cache statistics
            provider_stats = self.ai_provider.get_stats()
            result.cache_hits = provider_stats['cache']['hits']
            result.cache_misses = provider_stats['cache']['misses']

            # Step 13.5: Generate Remediation Plan
            stage_start = time.time()
            try:
                logger.info("Generating remediation plan...")
                vulnerable_code = report.proof_of_concept if report.proof_of_concept else None
                remediation_plan = self.remediation_engine.generate_remediation_plan(
                    report=report,
                    validation_result=result,
                    codebase_path=codebase_path,
                    vulnerable_code=vulnerable_code
                )
                result.remediation_plan = remediation_plan
                logger.info(f"Generated remediation plan with {len(remediation_plan.code_fixes)} code fixes, "
                           f"{len(remediation_plan.waf_rules)} WAF rules, "
                           f"{len(remediation_plan.compensating_controls)} compensating controls")
            except Exception as e:
                logger.error(f"Failed to generate remediation plan: {e}")
            stage_timings['remediation_plan'] = time.time() - stage_start

            # Step 14: Execute Integrations
            stage_start = time.time()
            try:
                if self.config.get('integrations', {}).get('enabled', False):
                    logger.info("Executing integrations...")
                    integration_results = self.integration_manager.execute_integrations(result)
                    result.integration_results = integration_results

                    # Log integration results
                    success_count = sum(1 for r in integration_results if r.status.value == 'SUCCESS')
                    logger.info(f"Integrations executed: {success_count}/{len(integration_results)} successful")

                    for int_result in integration_results:
                        if int_result.status.value == 'SUCCESS':
                            logger.info(f"  ✓ {int_result.integration_name}: {int_result.message}")
                            if int_result.external_url:
                                logger.info(f"    URL: {int_result.external_url}")
                        else:
                            logger.warning(f"  ✗ {int_result.integration_name}: {int_result.message}")
                else:
                    logger.debug("Integrations disabled")
            except Exception as e:
                logger.error(f"Failed to execute integrations: {e}")
            stage_timings['integrations'] = time.time() - stage_start

            # Step 15: Update Researcher Reputation
            stage_start = time.time()
            try:
                if hasattr(report, 'researcher_id') and report.researcher_id:
                    logger.info(f"Updating reputation for researcher {report.researcher_id}")
                    researcher_username = getattr(report, 'researcher_username', None)
                    reputation = self.reputation_manager.update_reputation(
                        researcher_id=report.researcher_id,
                        validation_result=result,
                        username=researcher_username
                    )
                    result.researcher_reputation = reputation

                    # Log reputation insights
                    logger.info(
                        f"Researcher reputation: {reputation.reputation_score.overall:.1f}/100, "
                        f"trust={reputation.trust_level.value}, "
                        f"fast_track={reputation.should_fast_track}"
                    )

                    # Add reputation insights to recommendations
                    if reputation.should_fast_track:
                        result.recommendations_security_team.insert(0,
                            f"⚡ FAST-TRACK: Trusted researcher (reputation: {reputation.reputation_score.overall:.1f}/100) - "
                            f"Priority level {reputation.fast_track.priority_level}, saves ~{reputation.fast_track.estimated_time_savings_minutes}min"
                        )

                    if reputation.is_spam_risk:
                        result.recommendations_security_team.insert(0,
                            f"⚠️ SPAM RISK: Researcher flagged as potential spam (risk: {reputation.spam_indicators.risk_score:.0f}/100) - "
                            f"Review carefully"
                        )

                    structured_logger.info(
                        "Researcher reputation updated",
                        researcher_id=report.researcher_id,
                        reputation_score=reputation.reputation_score.overall,
                        trust_level=reputation.trust_level.value,
                        fast_track=reputation.should_fast_track
                    )
            except Exception as e:
                logger.error(f"Failed to update researcher reputation: {e}")
            stage_timings['reputation_update'] = time.time() - stage_start

            # Step 16: Calculate Bounty Payout Recommendation
            stage_start = time.time()
            try:
                if result.verdict.value == 'VALID':
                    logger.info("Calculating bounty payout recommendation")

                    # CRITICAL: Check if codebase analysis was performed
                    if not code_analysis:
                        logger.warning("⚠️ PAYOUT BLOCKED: Codebase analysis is required before approving payout")
                        result.recommendations_security_team.insert(0,
                            "🚫 PAYOUT BLOCKED: Codebase analysis is MANDATORY before approving any payout. "
                            "Provide codebase_path to validate vulnerability exists in your code."
                        )
                        # Set payout to $0 with explanation
                        from bountybot.bounty_payout.models import PayoutRecommendation, SeverityTier, PayoutJustification
                        justification_obj = PayoutJustification(
                            base_amount=0.0,
                            severity_multiplier=0.0,
                            impact_multiplier=0.0,
                            reputation_multiplier=0.0,
                            market_adjustment=0.0,
                            budget_adjustment=0.0,
                            factors=[],
                            reasoning="Payout blocked: Codebase analysis required to confirm vulnerability exists in organization's code"
                        )
                        result.payout_recommendation = PayoutRecommendation(
                            recommended_amount=0.0,
                            min_amount=0.0,
                            max_amount=0.0,
                            severity_tier=SeverityTier.LOW,  # Use LOW instead of NONE
                            confidence=0.0,
                            justification=justification_obj
                        )
                    else:
                        # Check if vulnerability was confirmed in codebase
                        if not code_analysis.vulnerable_code_found:
                            logger.warning("⚠️ PAYOUT REDUCED: No vulnerable code patterns found in codebase")
                            result.recommendations_security_team.insert(0,
                                "⚠️ WARNING: No vulnerable code patterns found in codebase analysis. "
                                "Vulnerability may not exist in your specific implementation. Consider reduced payout or rejection."
                            )

                        # Check if PoC execution failed
                        if hasattr(result, 'poc_execution_result') and result.poc_execution_result:
                            if not result.poc_execution_result.vulnerability_confirmed:
                                logger.warning("⚠️ PAYOUT REDUCED: PoC execution failed to confirm vulnerability")
                                result.recommendations_security_team.insert(0,
                                    "⚠️ WARNING: PoC failed to exploit vulnerability. May be false positive or protected by controls. "
                                    "Consider reduced payout or additional verification."
                                )

                        reputation = getattr(result, 'researcher_reputation', None)
                        payout_recommendation = self.payout_engine.calculate_payout(
                            validation_result=result,
                            researcher_reputation=reputation
                        )
                        result.payout_recommendation = payout_recommendation

                        logger.info(
                            f"Payout recommendation: ${payout_recommendation.recommended_amount:,.2f} "
                            f"({payout_recommendation.severity_tier.value}, "
                            f"range: ${payout_recommendation.min_amount:,.2f}-${payout_recommendation.max_amount:,.2f})"
                        )

                        # Add payout to recommendations
                        result.recommendations_security_team.insert(0,
                            f"💰 PAYOUT: ${payout_recommendation.recommended_amount:,.2f} "
                            f"({payout_recommendation.severity_tier.value.UPPER()}, "
                            f"confidence: {payout_recommendation.confidence:.0%})"
                    )
            except Exception as e:
                logger.error(f"Failed to calculate payout recommendation: {e}")
            stage_timings['payout_calculation'] = time.time() - stage_start

            # Log completion
            structured_logger.audit_log(
                action="validate_report",
                resource=report_path,
                result=result.verdict.value,
                confidence=result.confidence,
                processing_time=result.processing_time_seconds,
                cost=result.total_cost
            )

            return result

        except Exception as e:
            logger.error(f"Error during validation: {e}")
            raise

    def analyze_report_clustering(self, reports: List[Any], min_cluster_size: int = 2) -> Any:
        """
        Analyze clustering and similarity across multiple reports.

        Args:
            reports: List of reports to analyze
            min_cluster_size: Minimum cluster size

        Returns:
            ClusteringResult object
        """
        logger.info(f"Analyzing clustering for {len(reports)} reports")
        return self.clustering_engine.cluster_reports(
            reports=reports,
            min_cluster_size=min_cluster_size
        )

    def find_similar_reports(self, report: Any, candidate_reports: List[Any], threshold: float = 0.7) -> Any:
        """
        Find similar reports to a given report.

        Args:
            report: Report to analyze
            candidate_reports: List of candidate reports
            threshold: Similarity threshold

        Returns:
            SimilarityAnalysis object
        """
        logger.info(f"Finding similar reports for report {getattr(report, 'report_id', 'unknown')}")
        return self.similarity_analyzer.analyze_similarity(
            report=report,
            candidate_reports=candidate_reports,
            threshold=threshold
        )

    def generate_communication_response(
        self,
        scenario: Any,
        context: Dict[str, Any],
        language: Any = None,
        tone: Any = None
    ) -> Any:
        """
        Generate communication response for a scenario.

        Args:
            scenario: Communication scenario
            context: Context dictionary
            language: Target language (optional)
            tone: Desired tone (optional)

        Returns:
            GeneratedResponse object
        """
        from bountybot.communication import Language, ToneType

        if language is None:
            language = Language.ENGLISH
        if tone is None:
            tone = ToneType.PROFESSIONAL

        logger.info(f"Generating communication response for scenario {scenario}")
        return self.response_generator.generate_response(
            scenario=scenario,
            context=context,
            language=language,
            tone=tone
        )

    def _parse_report(self, report_path: str) -> Report:
        """
        Parse report file based on extension.
        
        Args:
            report_path: Path to report file
            
        Returns:
            Parsed Report object
        """
        path = Path(report_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Report file not found: {report_path}")
        
        # Determine parser based on file extension
        extension = path.suffix.lower()

        if extension == '.json':
            parser = JSONParser()
        elif extension in ['.md', '.markdown']:
            parser = MarkdownParser()
        elif extension in ['.html', '.htm']:
            parser = BountyHTMLParser()
        else:
            # Default to text parser
            parser = TextParser()

        return parser.parse(path)

    def _get_scan_types_for_vulnerability(self, vulnerability_type: Optional[str]) -> List[str]:
        """
        Determine which scan types to run based on reported vulnerability type.

        Args:
            vulnerability_type: Reported vulnerability type

        Returns:
            List of scan types to perform
        """
        if not vulnerability_type:
            # Run all scans if type unknown
            return ['sqli', 'xss', 'cmdi', 'path_traversal', 'ssrf', 'open_redirect']

        vuln_lower = vulnerability_type.lower()

        # Map vulnerability types to scan types
        if 'sql' in vuln_lower or 'injection' in vuln_lower:
            return ['sqli']
        elif 'xss' in vuln_lower or 'cross-site scripting' in vuln_lower:
            return ['xss']
        elif 'command' in vuln_lower:
            return ['cmdi']
        elif 'path' in vuln_lower or 'traversal' in vuln_lower or 'lfi' in vuln_lower:
            return ['path_traversal']
        elif 'ssrf' in vuln_lower:
            return ['ssrf']
        elif 'redirect' in vuln_lower:
            return ['open_redirect']
        else:
            # Run all scans for unknown types
            return ['sqli', 'xss', 'cmdi', 'path_traversal', 'ssrf', 'open_redirect']

    def save_results(self, result: ValidationResult, output_formats: list, output_dir: str):
        """
        Save validation results in specified formats.
        
        Args:
            result: Validation result
            output_formats: List of output formats (json, markdown, terminal)
            output_dir: Output directory
        """
        include_timestamp = self.config.get('output', {}).get('include_timestamps', True)
        
        saved_files = []
        
        for format_name in output_formats:
            try:
                if format_name == 'json':
                    file_path = JSONOutput.save(result, output_dir, include_timestamp)
                    saved_files.append(file_path)

                elif format_name == 'markdown':
                    file_path = MarkdownOutput.save(result, output_dir, include_timestamp)
                    saved_files.append(file_path)

                elif format_name == 'html':
                    file_path = HTMLOutput.save(result, output_dir, include_timestamp)
                    saved_files.append(file_path)

                else:
                    logger.warning(f"Unknown output format: {format_name}")

            except Exception as e:
                logger.error(f"Error saving {format_name} output: {e}")

        if saved_files:
            logger.info(f"Results saved to {len(saved_files)} file(s)")
            for file_path in saved_files:
                logger.info(f"Saved: {file_path}")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get validation statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            'ai_provider': self.ai_provider.get_stats(),
        }

