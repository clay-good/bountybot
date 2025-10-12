import pytest
import json
import tempfile
from pathlib import Path

from bountybot.parsers.json_parser import JSONParser
from bountybot.parsers.markdown_parser import MarkdownParser
from bountybot.parsers.text_parser import TextParser
from bountybot.models import Severity


class TestJSONParser:
    """Tests for JSON parser."""
    
    def test_parse_valid_json(self):
        """Test parsing valid JSON report."""
        report_data = {
            "title": "SQL Injection in Login",
            "researcher": "test_researcher",
            "vulnerability_type": "sql injection",
            "severity": "HIGH",
            "description": "SQL injection vulnerability found",
            "steps_to_reproduce": "1. Go to login\n2. Enter payload",
            "proof_of_concept": "' OR 1=1--",
            "impact": "Data breach possible",
            "affected_component": "/api/login"
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(report_data, f)
            temp_path = f.name
        
        try:
            parser = JSONParser()
            report = parser.parse(temp_path)
            
            assert report.title == "SQL Injection in Login"
            assert report.researcher == "test_researcher"
            assert report.vulnerability_type == "sql injection"
            assert report.severity == Severity.HIGH
            assert "SQL injection" in report.description
        finally:
            Path(temp_path).unlink()
    
    def test_parse_minimal_json(self):
        """Test parsing JSON with minimal fields."""
        report_data = {
            "title": "Test Vulnerability"
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(report_data, f)
            temp_path = f.name
        
        try:
            parser = JSONParser()
            report = parser.parse(temp_path)
            
            assert report.title == "Test Vulnerability"
            assert report.description is None
        finally:
            Path(temp_path).unlink()
    
    def test_parse_invalid_json(self):
        """Test parsing invalid JSON."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{ invalid json }")
            temp_path = f.name
        
        try:
            parser = JSONParser()
            with pytest.raises(Exception):
                parser.parse(temp_path)
        finally:
            Path(temp_path).unlink()


class TestMarkdownParser:
    """Tests for Markdown parser."""
    
    def test_parse_valid_markdown(self):
        """Test parsing valid Markdown report."""
        markdown_content = """# XSS Vulnerability

## Researcher
security_expert

## Vulnerability Type
xss

## Severity
MEDIUM

## Description
Cross-site scripting vulnerability found in comment section.

## Steps to Reproduce
1. Navigate to comments
2. Submit malicious script
3. Script executes

## Proof of Concept
<script>alert(1)</script>

## Impact
Session hijacking possible
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(markdown_content)
            temp_path = f.name
        
        try:
            parser = MarkdownParser()
            report = parser.parse(temp_path)
            
            assert report.title == "XSS Vulnerability"
            assert report.researcher == "security_expert"
            assert report.vulnerability_type == "xss"
            assert report.severity == Severity.MEDIUM
        finally:
            Path(temp_path).unlink()
    
    def test_parse_markdown_with_missing_sections(self):
        """Test parsing Markdown with missing sections."""
        markdown_content = """# Test Report

Some description here.
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(markdown_content)
            temp_path = f.name
        
        try:
            parser = MarkdownParser()
            report = parser.parse(temp_path)
            
            assert report.title == "Test Report"
        finally:
            Path(temp_path).unlink()


class TestTextParser:
    """Tests for text parser."""
    
    def test_parse_text_report(self):
        """Test parsing plain text report."""
        text_content = """SQL Injection Vulnerability

Found a SQL injection in the search endpoint.

Steps:
1. Go to search
2. Enter ' OR 1=1--
3. All records returned

This is a critical vulnerability.
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(text_content)
            temp_path = f.name
        
        try:
            parser = TextParser()
            report = parser.parse(temp_path)
            
            assert "SQL Injection" in report.title
            assert "search endpoint" in report.description
        finally:
            Path(temp_path).unlink()
    
    def test_parse_empty_text(self):
        """Test parsing empty text file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("")
            temp_path = f.name
        
        try:
            parser = TextParser()
            with pytest.raises(ValueError):
                parser.parse(temp_path)
        finally:
            Path(temp_path).unlink()

