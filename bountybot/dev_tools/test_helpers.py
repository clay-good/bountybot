"""
Test helpers and utilities for BountyBot development.

Provides fixtures, assertions, and testing utilities.
"""

import json
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional, List
from unittest.mock import Mock, MagicMock

from bountybot.models import Report, Verdict
from bountybot.dev_tools.mock_data import MockDataGenerator


class TestHelpers:
    """
    Test helpers and utilities.
    
    Features:
    - Create temporary test files
    - Mock AI provider responses
    - Assert validation results
    - Compare reports and results
    """
    
    @staticmethod
    def create_temp_report(
        report_data: Optional[Dict[str, Any]] = None,
        format: str = 'json'
    ) -> str:
        """
        Create temporary report file.
        
        Args:
            report_data: Report data dictionary
            format: File format (json, md, html)
            
        Returns:
            Path to temporary file
        """
        if report_data is None:
            report_data = MockDataGenerator.generate_report()
        
        suffix = f'.{format}'
        
        with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
            if format == 'json':
                json.dump(report_data, f, indent=2)
            elif format == 'md':
                TestHelpers._write_markdown_report(f, report_data)
            elif format == 'html':
                TestHelpers._write_html_report(f, report_data)
            
            return f.name
    
    @staticmethod
    def _write_markdown_report(f, report_data: Dict[str, Any]):
        """Write report in Markdown format."""
        f.write(f"# {report_data['title']}\n\n")
        f.write(f"**ID:** {report_data['id']}\n\n")
        f.write(f"**Vulnerability Type:** {report_data['vulnerability_type']}\n\n")
        f.write(f"**Severity:** {report_data['severity']}\n\n")
        f.write(f"## Description\n\n{report_data['description']}\n\n")
        
        if report_data.get('steps_to_reproduce'):
            f.write(f"## Steps to Reproduce\n\n{report_data['steps_to_reproduce']}\n\n")
        
        if report_data.get('impact'):
            f.write(f"## Impact\n\n{report_data['impact']}\n\n")
    
    @staticmethod
    def _write_html_report(f, report_data: Dict[str, Any]):
        """Write report in HTML format."""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{report_data['title']}</title>
</head>
<body>
    <h1>{report_data['title']}</h1>
    <p><strong>ID:</strong> {report_data['id']}</p>
    <p><strong>Vulnerability Type:</strong> {report_data['vulnerability_type']}</p>
    <p><strong>Severity:</strong> {report_data['severity']}</p>
    <h2>Description</h2>
    <p>{report_data['description']}</p>
    <h2>Steps to Reproduce</h2>
    <p>{report_data.get('steps_to_reproduce', 'N/A')}</p>
    <h2>Impact</h2>
    <p>{report_data.get('impact', 'N/A')}</p>
</body>
</html>
"""
        f.write(html)
    
    @staticmethod
    def create_temp_codebase(files: Dict[str, str]) -> str:
        """
        Create temporary codebase directory.
        
        Args:
            files: Dictionary mapping file paths to content
            
        Returns:
            Path to temporary directory
        """
        tmpdir = tempfile.mkdtemp()
        
        for file_path, content in files.items():
            full_path = Path(tmpdir) / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(full_path, 'w') as f:
                f.write(content)
        
        return tmpdir
    
    @staticmethod
    def mock_ai_provider(
        response: Optional[str] = None,
        cost: float = 0.01,
        input_tokens: int = 100,
        output_tokens: int = 50
    ) -> Mock:
        """
        Create mock AI provider.
        
        Args:
            response: Mock response text
            cost: Mock cost
            input_tokens: Mock input tokens
            output_tokens: Mock output tokens
            
        Returns:
            Mock AI provider
        """
        provider = Mock()
        
        default_response = {
            'response': response or "This is a valid security vulnerability.",
            'cost': cost,
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
            'cache_read_tokens': 0,
            'cache_creation_tokens': 0
        }
        
        provider.complete.return_value = default_response
        provider.complete_with_caching.return_value = default_response
        
        return provider
    
    @staticmethod
    def mock_async_ai_provider(
        response: Optional[str] = None,
        cost: float = 0.01,
        input_tokens: int = 100,
        output_tokens: int = 50
    ) -> Mock:
        """
        Create mock async AI provider.
        
        Args:
            response: Mock response text
            cost: Mock cost
            input_tokens: Mock input tokens
            output_tokens: Mock output tokens
            
        Returns:
            Mock async AI provider
        """
        provider = Mock()
        
        default_response = {
            'response': response or "This is a valid security vulnerability.",
            'cost': cost,
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
            'cache_read_tokens': 0,
            'cache_creation_tokens': 0
        }
        
        # Create async mock
        async def async_complete(*args, **kwargs):
            return default_response
        
        provider.complete_async = async_complete
        provider.complete_with_caching_async = async_complete
        
        return provider
    
    @staticmethod
    def assert_validation_result(
        result,
        expected_verdict: Optional[str] = None,
        min_confidence: Optional[float] = None,
        expected_severity: Optional[str] = None
    ):
        """
        Assert validation result properties.
        
        Args:
            result: ValidationResult object
            expected_verdict: Expected verdict
            min_confidence: Minimum confidence threshold
            expected_severity: Expected severity
        """
        if expected_verdict:
            assert result.verdict.value == expected_verdict, \
                f"Expected verdict {expected_verdict}, got {result.verdict.value}"
        
        if min_confidence is not None:
            assert result.confidence >= min_confidence, \
                f"Expected confidence >= {min_confidence}, got {result.confidence}"
        
        if expected_severity:
            assert result.severity == expected_severity, \
                f"Expected severity {expected_severity}, got {result.severity}"
    
    @staticmethod
    def assert_report_parsed(report: Report):
        """
        Assert report was parsed correctly.
        
        Args:
            report: Report object
        """
        assert report.id is not None, "Report ID is None"
        assert report.title is not None, "Report title is None"
        assert report.description is not None, "Report description is None"
        assert report.vulnerability_type is not None, "Vulnerability type is None"
    
    @staticmethod
    def compare_reports(report1: Report, report2: Report) -> Dict[str, bool]:
        """
        Compare two reports.
        
        Args:
            report1: First report
            report2: Second report
            
        Returns:
            Dictionary of comparison results
        """
        return {
            'id_match': report1.id == report2.id,
            'title_match': report1.title == report2.title,
            'vuln_type_match': report1.vulnerability_type == report2.vulnerability_type,
            'severity_match': report1.severity == report2.severity,
            'description_match': report1.description == report2.description
        }
    
    @staticmethod
    def compare_validation_results(
        result1: Dict[str, Any],
        result2: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Compare two validation results.
        
        Args:
            result1: First validation result
            result2: Second validation result
            
        Returns:
            Dictionary of comparison results
        """
        return {
            'verdict_match': result1.get('verdict') == result2.get('verdict'),
            'confidence_diff': abs(result1.get('confidence', 0) - result2.get('confidence', 0)),
            'severity_match': result1.get('severity') == result2.get('severity'),
            'reasoning_similarity': TestHelpers._calculate_similarity(
                result1.get('reasoning', ''),
                result2.get('reasoning', '')
            )
        }
    
    @staticmethod
    def _calculate_similarity(text1: str, text2: str) -> float:
        """Calculate simple text similarity."""
        if not text1 or not text2:
            return 0.0
        
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        if not words1 or not words2:
            return 0.0
        
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        
        return len(intersection) / len(union)
    
    @staticmethod
    def create_fixture_factory(fixture_type: str):
        """
        Create fixture factory for specific type.
        
        Args:
            fixture_type: Type of fixture (report, http_request, validation_result)
            
        Returns:
            Factory function
        """
        factories = {
            'report': MockDataGenerator.generate_report,
            'http_request': MockDataGenerator.generate_http_request,
            'validation_result': MockDataGenerator.generate_validation_result
        }
        
        return factories.get(fixture_type, MockDataGenerator.generate_report)
    
    @staticmethod
    def measure_performance(func, *args, **kwargs) -> Dict[str, Any]:
        """
        Measure function performance.
        
        Args:
            func: Function to measure
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Performance metrics dictionary
        """
        import time
        
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        
        return {
            'result': result,
            'duration': end_time - start_time,
            'start_time': start_time,
            'end_time': end_time
        }

