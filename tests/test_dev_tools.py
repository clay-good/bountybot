"""
Tests for development tools.
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock

from bountybot.dev_tools.mock_data import MockDataGenerator
from bountybot.dev_tools.test_helpers import TestHelpers
from bountybot.models import Report


class TestMockDataGenerator:
    """Test MockDataGenerator functionality."""
    
    def test_generate_report(self):
        """Test generating mock report."""
        report = MockDataGenerator.generate_report()
        
        assert 'id' in report
        assert 'title' in report
        assert 'description' in report
        assert 'vulnerability_type' in report
        assert 'severity' in report
        assert report['id'].startswith('MOCK-')
    
    def test_generate_report_with_specific_vuln_type(self):
        """Test generating report with specific vulnerability type."""
        report = MockDataGenerator.generate_report(vulnerability_type='SQL Injection')
        
        assert report['vulnerability_type'] == 'SQL Injection'
        assert 'SQL Injection' in report['title']
    
    def test_generate_report_with_specific_severity(self):
        """Test generating report with specific severity."""
        report = MockDataGenerator.generate_report(severity='Critical')
        
        assert report['severity'] == 'Critical'
    
    def test_generate_report_with_specific_platform(self):
        """Test generating report with specific platform."""
        report = MockDataGenerator.generate_report(platform='HackerOne')
        
        assert report['platform'] == 'HackerOne'
    
    def test_generate_report_without_http_requests(self):
        """Test generating report without HTTP requests."""
        report = MockDataGenerator.generate_report(include_http_requests=False)
        
        assert '```' not in report['description']
    
    def test_generate_report_without_steps(self):
        """Test generating report without steps."""
        report = MockDataGenerator.generate_report(include_steps=False)
        
        assert report['steps_to_reproduce'] is None
    
    def test_generate_report_without_impact(self):
        """Test generating report without impact."""
        report = MockDataGenerator.generate_report(include_impact=False)
        
        assert report['impact'] is None
    
    def test_generate_http_request(self):
        """Test generating HTTP request."""
        request = MockDataGenerator.generate_http_request()
        
        assert 'method' in request
        assert 'url' in request
        assert 'headers' in request
        assert request['method'] == 'GET'
    
    def test_generate_http_request_with_custom_method(self):
        """Test generating HTTP request with custom method."""
        request = MockDataGenerator.generate_http_request(method='POST')
        
        assert request['method'] == 'POST'
    
    def test_generate_http_request_with_body(self):
        """Test generating HTTP request with body."""
        body = '{"key": "value"}'
        request = MockDataGenerator.generate_http_request(body=body)
        
        assert request['body'] == body
    
    def test_generate_validation_result(self):
        """Test generating validation result."""
        result = MockDataGenerator.generate_validation_result()
        
        assert 'verdict' in result
        assert 'confidence' in result
        assert 'severity' in result
        assert 'reasoning' in result
        assert result['verdict'] in ['VALID', 'INVALID', 'UNCERTAIN']
    
    def test_generate_validation_result_with_specific_verdict(self):
        """Test generating validation result with specific verdict."""
        result = MockDataGenerator.generate_validation_result(verdict='VALID')
        
        assert result['verdict'] == 'VALID'
    
    def test_generate_validation_result_with_specific_confidence(self):
        """Test generating validation result with specific confidence."""
        result = MockDataGenerator.generate_validation_result(confidence=0.95)
        
        assert result['confidence'] == 0.95
    
    def test_generate_batch_reports(self):
        """Test generating batch of reports."""
        reports = MockDataGenerator.generate_batch_reports(count=5)
        
        assert len(reports) == 5
        assert all('id' in r for r in reports)
    
    def test_generate_test_suite(self):
        """Test generating test suite."""
        suite = MockDataGenerator.generate_test_suite()
        
        assert 'valid_reports' in suite
        assert 'invalid_reports' in suite
        assert 'edge_cases' in suite
        assert len(suite['valid_reports']) == 3
        assert len(suite['invalid_reports']) == 3
        assert len(suite['edge_cases']) == 3


class TestTestHelpers:
    """Test TestHelpers functionality."""
    
    def test_create_temp_report_json(self):
        """Test creating temporary JSON report."""
        report_path = TestHelpers.create_temp_report(format='json')
        
        assert Path(report_path).exists()
        assert report_path.endswith('.json')
        
        # Verify content
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        assert 'id' in data
        assert 'title' in data
        
        # Cleanup
        Path(report_path).unlink()
    
    def test_create_temp_report_markdown(self):
        """Test creating temporary Markdown report."""
        report_path = TestHelpers.create_temp_report(format='md')
        
        assert Path(report_path).exists()
        assert report_path.endswith('.md')
        
        # Verify content
        with open(report_path, 'r') as f:
            content = f.read()
        
        assert '# ' in content  # Markdown header
        
        # Cleanup
        Path(report_path).unlink()
    
    def test_create_temp_report_html(self):
        """Test creating temporary HTML report."""
        report_path = TestHelpers.create_temp_report(format='html')
        
        assert Path(report_path).exists()
        assert report_path.endswith('.html')
        
        # Verify content
        with open(report_path, 'r') as f:
            content = f.read()
        
        assert '<!DOCTYPE html>' in content
        
        # Cleanup
        Path(report_path).unlink()
    
    def test_create_temp_codebase(self):
        """Test creating temporary codebase."""
        files = {
            'main.py': 'print("Hello")',
            'lib/utils.py': 'def helper(): pass',
            'tests/test_main.py': 'def test_main(): pass'
        }
        
        codebase_path = TestHelpers.create_temp_codebase(files)
        
        assert Path(codebase_path).exists()
        assert (Path(codebase_path) / 'main.py').exists()
        assert (Path(codebase_path) / 'lib' / 'utils.py').exists()
        assert (Path(codebase_path) / 'tests' / 'test_main.py').exists()
    
    def test_mock_ai_provider(self):
        """Test creating mock AI provider."""
        provider = TestHelpers.mock_ai_provider(response="Test response")
        
        result = provider.complete("Test prompt")
        
        assert result['response'] == "Test response"
        assert 'cost' in result
        assert 'input_tokens' in result
        assert 'output_tokens' in result
    
    def test_mock_async_ai_provider(self):
        """Test creating mock async AI provider."""
        import asyncio
        
        provider = TestHelpers.mock_async_ai_provider(response="Test response")
        
        async def test():
            result = await provider.complete_async("Test prompt")
            return result
        
        result = asyncio.run(test())
        
        assert result['response'] == "Test response"
        assert 'cost' in result
    
    def test_assert_validation_result(self):
        """Test asserting validation result."""
        result = Mock()
        result.verdict.value = 'VALID'
        result.confidence = 0.95
        result.severity = 'High'
        
        # Should not raise
        TestHelpers.assert_validation_result(
            result,
            expected_verdict='VALID',
            min_confidence=0.9,
            expected_severity='High'
        )
    
    def test_assert_validation_result_fails(self):
        """Test asserting validation result fails."""
        result = Mock()
        result.verdict.value = 'INVALID'
        result.confidence = 0.5
        result.severity = 'Low'
        
        with pytest.raises(AssertionError):
            TestHelpers.assert_validation_result(
                result,
                expected_verdict='VALID'
            )
    
    def test_compare_validation_results(self):
        """Test comparing validation results."""
        result1 = {
            'verdict': 'VALID',
            'confidence': 0.95,
            'severity': 'High',
            'reasoning': 'This is a valid vulnerability'
        }
        
        result2 = {
            'verdict': 'VALID',
            'confidence': 0.93,
            'severity': 'High',
            'reasoning': 'This is a valid security issue'
        }
        
        comparison = TestHelpers.compare_validation_results(result1, result2)
        
        assert comparison['verdict_match']
        assert comparison['confidence_diff'] < 0.05
        assert comparison['severity_match']
        assert comparison['reasoning_similarity'] > 0.0
    
    def test_create_fixture_factory(self):
        """Test creating fixture factory."""
        factory = TestHelpers.create_fixture_factory('report')
        
        report = factory()
        
        assert 'id' in report
        assert 'title' in report
    
    def test_measure_performance(self):
        """Test measuring performance."""
        def test_func(x, y):
            return x + y
        
        metrics = TestHelpers.measure_performance(test_func, 2, 3)
        
        assert metrics['result'] == 5
        assert 'duration' in metrics
        assert 'start_time' in metrics
        assert 'end_time' in metrics
        assert metrics['duration'] >= 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

