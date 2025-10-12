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

logger = logging.getLogger(__name__)


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
    
    def validate_report(self, 
                       report_path: str,
                       codebase_path: Optional[str] = None,
                       target_url: Optional[str] = None) -> ValidationResult:
        """
        Validate a bug bounty report.
        
        Args:
            report_path: Path to bug bounty report file
            codebase_path: Optional path to codebase for static analysis
            target_url: Optional target URL for dynamic testing
            
        Returns:
            Validation result
        """
        start_time = time.time()

        try:
            # Step 1: Parse report
            logger.info(f"Parsing report: {report_path}")
            report = self._parse_report(report_path)
            logger.info(f"Successfully parsed report: {report.title}")

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

            # Calculate processing time
            result.processing_time_seconds = time.time() - start_time
            result.total_cost = self.ai_provider.total_cost

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

