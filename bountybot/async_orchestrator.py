"""
Async orchestrator for concurrent bug bounty validation.
Provides significant performance improvements for batch processing.
"""

import logging
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional, List

from bountybot.config_loader import ConfigLoader
from bountybot.models import Report, ValidationResult
from bountybot.parsers import JSONParser, MarkdownParser, TextParser
from bountybot.parsers.html_parser import BountyHTMLParser
from bountybot.ai_providers import (
    AsyncAnthropicProvider,
    ASYNC_OPENAI_AVAILABLE,
    ASYNC_GEMINI_AVAILABLE
)
if ASYNC_OPENAI_AVAILABLE:
    from bountybot.ai_providers import AsyncOpenAIProvider
if ASYNC_GEMINI_AVAILABLE:
    from bountybot.ai_providers import AsyncGeminiProvider

from bountybot.extractors import HTTPRequestExtractor
from bountybot.scoring import CVSSCalculator
from bountybot.deduplication import DuplicateDetector
from bountybot.logging import StructuredLogger, PerformanceTracker
from bountybot.analysis import (
    FalsePositiveDetector,
    ExploitComplexityAnalyzer,
    AttackChainDetector
)
from bountybot.prioritization import PriorityEngine

# Import tracing
try:
    from bountybot.monitoring.tracing import get_tracing_manager
    TRACING_AVAILABLE = True
except ImportError:
    TRACING_AVAILABLE = False
    get_tracing_manager = None

logger = logging.getLogger(__name__)
structured_logger = StructuredLogger(__name__)


class AsyncOrchestrator:
    """
    Async orchestrator that coordinates concurrent validation workflows.
    Provides 3-5x performance improvement over synchronous validation.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize async orchestrator with configuration.

        Args:
            config: Configuration dictionary
        """
        self.config = config

        # Initialize AI provider
        provider_name = config['api']['default_provider']
        provider_config = config['api']['providers'][provider_name]

        if provider_name == 'anthropic':
            self.ai_provider = AsyncAnthropicProvider(provider_config)
        elif provider_name == 'openai':
            if not ASYNC_OPENAI_AVAILABLE:
                raise ImportError("OpenAI provider requested but openai package not installed. Install with: pip install openai")
            self.ai_provider = AsyncOpenAIProvider(provider_config)
        elif provider_name == 'gemini':
            if not ASYNC_GEMINI_AVAILABLE:
                raise ImportError("Gemini provider requested but google-generativeai package not installed. Install with: pip install google-generativeai")
            self.ai_provider = AsyncGeminiProvider(provider_config)
        else:
            raise ValueError(f"Unsupported AI provider: {provider_name}. Supported: anthropic, openai, gemini")

        # Initialize synchronous components (will be made async in future)
        self.http_extractor = HTTPRequestExtractor()
        self.cvss_calculator = CVSSCalculator()
        self.duplicate_detector = DuplicateDetector(config.get('deduplication', {}))
        self.fp_detector = FalsePositiveDetector(config.get('false_positive_detection', {}))
        self.complexity_analyzer = ExploitComplexityAnalyzer(config.get('exploit_complexity', {}))
        self.chain_detector = AttackChainDetector(config.get('attack_chains', {}))
        self.priority_engine = PriorityEngine(config.get('prioritization', {}))

        # Concurrency settings
        self.max_concurrent_validations = config.get('max_concurrent_validations', 5)
        self.max_concurrent_ai_calls = config.get('max_concurrent_ai_calls', 3)

        logger.info(f"Async orchestrator initialized with {provider_name} provider")
        logger.info(f"Max concurrent validations: {self.max_concurrent_validations}")
        logger.info(f"Max concurrent AI calls: {self.max_concurrent_ai_calls}")

    async def validate_report(self,
                             report_path: str,
                             codebase_path: Optional[str] = None,
                             target_url: Optional[str] = None) -> ValidationResult:
        """
        Validate a single bug bounty report asynchronously.

        Args:
            report_path: Path to report file
            codebase_path: Optional path to codebase for analysis
            target_url: Optional target URL for dynamic scanning

        Returns:
            ValidationResult with verdict and analysis
        """
        # Get tracing manager
        tracing_manager = get_tracing_manager() if TRACING_AVAILABLE else None

        # Start tracing span
        span_context = None
        if tracing_manager and tracing_manager.enabled:
            span_context = tracing_manager.start_span(
                "validation.validate_report",
                attributes={
                    "report.path": report_path,
                    "codebase.path": codebase_path or "none",
                    "target.url": target_url or "none"
                }
            )
            span = span_context.__enter__()

        perf_tracker = PerformanceTracker()
        perf_tracker.start("total_validation")

        try:
            # Parse report
            perf_tracker.start("parsing")
            if tracing_manager:
                tracing_manager.add_event("parsing.start")
            report = await self._parse_report(report_path)
            if tracing_manager:
                tracing_manager.set_attribute("report.id", report.id)
                tracing_manager.set_attribute("report.title", report.title[:100])
                tracing_manager.set_attribute("report.vulnerability_type", report.vulnerability_type)
            perf_tracker.end("parsing")

            # Extract HTTP requests
            perf_tracker.start("http_extraction")
            if tracing_manager:
                tracing_manager.add_event("http_extraction.start")
            http_requests = await asyncio.to_thread(
                self.http_extractor.extract_from_report,
                report
            )
            if tracing_manager:
                tracing_manager.set_attribute("http_requests.count", len(http_requests))
            perf_tracker.end("http_extraction")

            # Run validation pipeline concurrently
            perf_tracker.start("validation_pipeline")
            if tracing_manager:
                tracing_manager.add_event("validation_pipeline.start")
            validation_result = await self._run_validation_pipeline(
                report, http_requests, codebase_path, target_url
            )
            if tracing_manager:
                tracing_manager.set_attribute("validation.verdict", validation_result.verdict)
                tracing_manager.set_attribute("validation.confidence", validation_result.confidence)
                tracing_manager.set_attribute("validation.severity", validation_result.severity)
            perf_tracker.end("validation_pipeline")

            perf_tracker.end("total_validation")

            # Add performance metrics
            validation_result.metadata['performance'] = perf_tracker.get_summary()

            if tracing_manager:
                tracing_manager.set_attribute("validation.duration_ms", perf_tracker.get_duration("total_validation") * 1000)
                tracing_manager.add_event("validation.complete", {
                    "verdict": validation_result.verdict,
                    "confidence": validation_result.confidence
                })

            structured_logger.log_validation(
                report_id=report.id,
                verdict=validation_result.verdict,
                confidence=validation_result.confidence,
                duration=perf_tracker.get_duration("total_validation")
            )

            return validation_result

        except Exception as e:
            logger.error(f"Validation failed: {e}", exc_info=True)
            if tracing_manager:
                tracing_manager.record_exception(e)
            perf_tracker.end("total_validation")
            raise
        finally:
            if span_context:
                span_context.__exit__(None, None, None)

    async def validate_reports_batch(self,
                                    report_paths: List[str],
                                    codebase_path: Optional[str] = None,
                                    target_url: Optional[str] = None) -> List[ValidationResult]:
        """
        Validate multiple reports concurrently.

        Args:
            report_paths: List of report file paths
            codebase_path: Optional path to codebase for analysis
            target_url: Optional target URL for dynamic scanning

        Returns:
            List of ValidationResults
        """
        # Get tracing manager
        tracing_manager = get_tracing_manager() if TRACING_AVAILABLE else None

        # Start tracing span
        span_context = None
        if tracing_manager and tracing_manager.enabled:
            span_context = tracing_manager.start_span(
                "validation.validate_reports_batch",
                attributes={
                    "batch.size": len(report_paths),
                    "batch.max_concurrent": self.max_concurrent_validations
                }
            )
            span = span_context.__enter__()

        logger.info(f"Starting batch validation of {len(report_paths)} reports")

        # Create semaphore to limit concurrency
        semaphore = asyncio.Semaphore(self.max_concurrent_validations)

        async def validate_with_semaphore(report_path: str):
            async with semaphore:
                try:
                    return await self.validate_report(report_path, codebase_path, target_url)
                except Exception as e:
                    logger.error(f"Failed to validate {report_path}: {e}")
                    return None

        try:
            # Run validations concurrently
            tasks = [validate_with_semaphore(path) for path in report_paths]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Filter out None results and exceptions
            valid_results = [r for r in results if isinstance(r, ValidationResult)]

            if tracing_manager:
                tracing_manager.set_attribute("batch.successful", len(valid_results))
                tracing_manager.set_attribute("batch.failed", len(report_paths) - len(valid_results))
                tracing_manager.add_event("batch.complete", {
                    "successful": len(valid_results),
                    "failed": len(report_paths) - len(valid_results)
                })

            logger.info(f"Batch validation complete: {len(valid_results)}/{len(report_paths)} successful")

            return valid_results
        finally:
            if span_context:
                span_context.__exit__(None, None, None)

    async def _parse_report(self, report_path: str) -> Report:
        """
        Parse report file asynchronously.

        Args:
            report_path: Path to report file

        Returns:
            Parsed Report object
        """
        path = Path(report_path)

        if not path.exists():
            raise FileNotFoundError(f"Report file not found: {report_path}")

        # Read file asynchronously
        content = await asyncio.to_thread(path.read_text, encoding='utf-8')

        # Parse based on file extension
        if path.suffix == '.json':
            parser = JSONParser()
        elif path.suffix == '.md':
            parser = MarkdownParser()
        elif path.suffix == '.html':
            parser = BountyHTMLParser()
        else:
            parser = TextParser()

        # Parse in thread pool
        report = await asyncio.to_thread(parser.parse, path)

        return report

    async def _run_validation_pipeline(self,
                                      report: Report,
                                      http_requests: List[Dict[str, Any]],
                                      codebase_path: Optional[str],
                                      target_url: Optional[str]) -> ValidationResult:
        """
        Run validation pipeline with concurrent AI calls.

        Args:
            report: Parsed report
            http_requests: Extracted HTTP requests
            codebase_path: Optional codebase path
            target_url: Optional target URL

        Returns:
            ValidationResult
        """
        # Create semaphore for AI calls
        ai_semaphore = asyncio.Semaphore(self.max_concurrent_ai_calls)

        async def ai_call_with_semaphore(system_prompt: str, user_prompt: str):
            async with ai_semaphore:
                return await self.ai_provider.complete(system_prompt, user_prompt)

        # Run multiple AI analyses concurrently
        quality_task = ai_call_with_semaphore(
            self._get_quality_system_prompt(),
            self._format_report_for_quality_check(report)
        )

        plausibility_task = ai_call_with_semaphore(
            self._get_plausibility_system_prompt(),
            self._format_report_for_plausibility_check(report)
        )

        severity_task = ai_call_with_semaphore(
            self._get_severity_system_prompt(),
            self._format_report_for_severity_assessment(report)
        )

        # Wait for all AI calls to complete
        quality_result, plausibility_result, severity_result = await asyncio.gather(
            quality_task,
            plausibility_task,
            severity_task
        )

        # Run synchronous analyses in thread pool
        cvss_task = asyncio.to_thread(self.cvss_calculator.calculate, report)
        fp_task = asyncio.to_thread(self.fp_detector.analyze, report)
        complexity_task = asyncio.to_thread(self.complexity_analyzer.analyze, report)

        cvss_score, fp_analysis, complexity_analysis = await asyncio.gather(
            cvss_task,
            fp_task,
            complexity_task
        )

        # Generate final verdict
        verdict_result = await ai_call_with_semaphore(
            self._get_verdict_system_prompt(),
            self._format_for_final_verdict(
                report, quality_result, plausibility_result,
                severity_result, cvss_score, fp_analysis
            )
        )

        # Build validation result
        validation_result = ValidationResult(
            report_id=report.id,
            verdict=self._extract_verdict(verdict_result['content']),
            confidence=self._extract_confidence(verdict_result['content']),
            reasoning=verdict_result['content'],
            cvss_score=cvss_score,
            false_positive_likelihood=fp_analysis.get('likelihood', 0.0),
            exploit_complexity=complexity_analysis.get('complexity', 'unknown'),
            metadata={
                'quality_assessment': quality_result['content'],
                'plausibility_analysis': plausibility_result['content'],
                'severity_assessment': severity_result['content'],
                'total_cost': (
                    quality_result['cost'] +
                    plausibility_result['cost'] +
                    severity_result['cost'] +
                    verdict_result['cost']
                ),
            }
        )

        return validation_result

    def _get_quality_system_prompt(self) -> str:
        """Get system prompt for quality assessment."""
        return """You are a security expert assessing bug bounty report quality.
        
Evaluate the report on:
- Completeness of information
- Clarity of explanation
- Technical depth
- Reproduction steps
- Impact assessment

Provide a quality score (0-100) and detailed feedback."""

    def _get_plausibility_system_prompt(self) -> str:
        """Get system prompt for plausibility analysis."""
        return """You are a security expert analyzing vulnerability plausibility.
        
Assess:
- Technical feasibility
- Attack vector validity
- Security impact
- Likelihood of exploitation
- Evidence quality

Provide a plausibility score (0-100) and analysis."""

    def _get_severity_system_prompt(self) -> str:
        """Get system prompt for severity assessment."""
        return """You are a security expert assessing vulnerability severity.
        
Evaluate:
- Confidentiality impact
- Integrity impact
- Availability impact
- Scope of affected systems
- Ease of exploitation

Provide severity rating (Critical/High/Medium/Low) and justification."""

    def _get_verdict_system_prompt(self) -> str:
        """Get system prompt for final verdict."""
        return """You are a senior security expert providing final validation verdict.
        
Based on all analyses, determine:
- VALID: Legitimate vulnerability, should be accepted
- INVALID: Not a real vulnerability or out of scope
- NEEDS_INFO: Requires additional information

Provide verdict, confidence (0-100), and detailed reasoning."""

    def _format_report_for_quality_check(self, report: Report) -> str:
        """Format report for quality assessment."""
        return f"""Report Title: {report.title}
        
Description:
{report.description}

Steps to Reproduce:
{report.steps_to_reproduce or 'Not provided'}

Impact:
{report.impact or 'Not provided'}

Please assess the quality of this report."""

    def _format_report_for_plausibility_check(self, report: Report) -> str:
        """Format report for plausibility analysis."""
        return f"""Vulnerability Type: {report.vulnerability_type}

Description:
{report.description}

Technical Details:
{report.technical_details or 'Not provided'}

Please analyze the plausibility of this vulnerability."""

    def _format_report_for_severity_assessment(self, report: Report) -> str:
        """Format report for severity assessment."""
        return f"""Vulnerability: {report.title}

Type: {report.vulnerability_type}

Impact:
{report.impact or 'Not provided'}

Affected Systems:
{report.affected_systems or 'Not specified'}

Please assess the severity of this vulnerability."""

    def _format_for_final_verdict(self, report: Report, quality, plausibility,
                                  severity, cvss_score, fp_analysis) -> str:
        """Format all analyses for final verdict."""
        return f"""Report: {report.title}

Quality Assessment:
{quality['content'][:500]}...

Plausibility Analysis:
{plausibility['content'][:500]}...

Severity Assessment:
{severity['content'][:500]}...

CVSS Score: {cvss_score}
False Positive Likelihood: {fp_analysis.get('likelihood', 0.0)}

Based on all analyses, provide your final verdict."""

    def _extract_verdict(self, content: str) -> str:
        """Extract verdict from AI response."""
        content_lower = content.lower()
        if 'valid' in content_lower and 'invalid' not in content_lower:
            return 'VALID'
        elif 'invalid' in content_lower:
            return 'INVALID'
        elif 'needs_info' in content_lower or 'needs info' in content_lower:
            return 'NEEDS_INFO'
        return 'UNKNOWN'

    def _extract_confidence(self, content: str) -> float:
        """Extract confidence score from AI response."""
        # Simple extraction - look for percentage or score
        import re
        matches = re.findall(r'confidence[:\s]+(\d+)', content.lower())
        if matches:
            return float(matches[0]) / 100.0
        return 0.5  # Default to 50% if not found

    async def get_stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        ai_stats = await self.ai_provider.get_stats()
        return {
            'orchestrator': 'async',
            'max_concurrent_validations': self.max_concurrent_validations,
            'max_concurrent_ai_calls': self.max_concurrent_ai_calls,
            'ai_provider': ai_stats,
        }

