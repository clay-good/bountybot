import logging
import time
from pathlib import Path
from typing import Dict, Any, Optional

from bountybot.config_loader import ConfigLoader
from bountybot.models import Report, ValidationResult
from bountybot.parsers import JSONParser, MarkdownParser, TextParser
from bountybot.ai_providers import AnthropicProvider
from bountybot.validators import AIValidator, CodeAnalyzer
from bountybot.validators.report_validator import ReportValidator
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
        else:
            raise ValueError(f"Unsupported AI provider: {provider_name}")
        
        # Initialize validators
        self.ai_validator = AIValidator(self.ai_provider)
        self.code_analyzer = CodeAnalyzer(config.get('code_analysis', {}))
        self.report_validator = ReportValidator()

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

        logger.info("Orchestrator initialized with advanced features (CVSS, dedup, FP detection, complexity, chains, prioritization)")
    
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

            # Step 3: Code analysis (if codebase provided)
            code_analysis = None
            if codebase_path and self.config.get('code_analysis', {}).get('enabled', True):
                logger.info(f"Analyzing codebase: {codebase_path}")
                code_analysis = self.code_analyzer.analyze(
                    codebase_path,
                    vulnerability_type=report.vulnerability_type,
                    affected_files=report.affected_components
                )
                logger.info(f"Code analysis complete: {len(code_analysis.vulnerable_patterns)} patterns found")

            # Step 4: Dynamic testing (if target provided)
            dynamic_test = None
            if target_url and self.config.get('target_testing', {}).get('enabled', False):
                logger.warning("Dynamic testing not yet implemented")

            # Step 5: AI validation
            logger.info("Running AI validation")
            result = self.ai_validator.validate(report, code_analysis, dynamic_test)
            logger.info(f"AI validation complete: {result.verdict.value} ({result.confidence}% confidence)")

            # Step 6: Add extracted HTTP requests to result
            result.extracted_http_requests = http_requests
            result.http_validation_issues = http_validation_issues

            # Step 7: Generate PoC if vulnerability is valid
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
        else:
            # Default to text parser
            parser = TextParser()
        
        return parser.parse(path)
    
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

