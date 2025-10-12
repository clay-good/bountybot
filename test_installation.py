#!/usr/bin/env python3
"""
Installation and functionality test script for bountybot.
This script tests that bountybot can be installed and used from scratch.
"""

import sys
import subprocess
import tempfile
import os
from pathlib import Path

def run_command(cmd, cwd=None):
    """Run a command and return success status and output."""
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            cwd=cwd,
            timeout=60
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)

def test_imports():
    """Test that all main components can be imported."""
    print("Testing imports...")
    
    try:
        # Test main imports
        from bountybot import Orchestrator, ConfigLoader
        from bountybot import HTTPRequestExtractor, PoCGenerator
        from bountybot.models import Report, Severity, Verdict
        print("[PASS] All imports successful")
        return True
    except ImportError as e:
        print(f"[FAIL] Import failed: {e}")
        return False

def test_basic_functionality():
    """Test basic functionality without API calls."""
    print("Testing basic functionality...")
    
    try:
        # Test HTTP extraction
        from bountybot.extractors import HTTPRequestExtractor
        extractor = HTTPRequestExtractor()
        
        text = 'curl -X POST https://example.com/api/test -d \'{"test": "data"}\''
        requests = extractor._extract_curl(text)
        
        if len(requests) != 1:
            print(f"[FAIL] Expected 1 request, got {len(requests)}")
            return False
            
        req = requests[0]
        if req.method != "POST" or "example.com" not in req.url:
            print(f"[FAIL] Request extraction failed: {req.method} {req.url}")
            return False
            
        # Test PoC generation (minimal)
        from bountybot.generators import PoCGenerator
        from bountybot.models import Report, Severity
        
        generator = PoCGenerator()
        report = Report(
            title="Test Vulnerability",
            vulnerability_type="SQL Injection",
            severity=Severity.HIGH
        )
        
        poc = generator._generate_minimal_poc(report)
        if not poc.title or "Test Vulnerability" not in poc.title:
            print(f"[FAIL] PoC generation failed: {poc.title}")
            return False
            
        print("[PASS] Basic functionality working")
        return True
        
    except Exception as e:
        print(f"[FAIL] Basic functionality test failed: {e}")
        return False

def test_cli_help():
    """Test that CLI help works."""
    print("Testing CLI help...")
    
    success, stdout, stderr = run_command("python3 -m bountybot.cli --help")
    
    if not success:
        print(f"[FAIL] CLI help failed: {stderr}")
        return False
        
    if "bountybot - AI-powered bug bounty validation tool" not in stdout:
        print("[FAIL] CLI help output doesn't contain expected text")
        return False
        
    print("[PASS] CLI help working")
    return True

def test_example_parsing():
    """Test parsing example reports without AI validation."""
    print("Testing example report parsing...")
    
    try:
        from bountybot.parsers.json_parser import JSONParser
        from pathlib import Path

        # Test if example file exists
        example_path = Path("examples/sql_injection_report.json")
        if not example_path.exists():
            print(f"[FAIL] Example file not found: {example_path}")
            return False

        parser = JSONParser()
        report = parser.parse(example_path)
        
        if not report.title or not report.vulnerability_type:
            print("[FAIL] Report parsing failed - missing required fields")
            return False
            
        print("[PASS] Example report parsing working")
        return True
        
    except Exception as e:
        print(f"[FAIL] Example parsing test failed: {e}")
        return False

def test_config_loading():
    """Test configuration loading."""
    print("Testing configuration loading...")
    
    try:
        from bountybot.config_loader import ConfigLoader
        
        config_loader = ConfigLoader()
        config = config_loader.load()
        
        if not config or 'api' not in config:
            print("[FAIL] Configuration loading failed - missing api section")
            return False
            
        print("[PASS] Configuration loading working")
        return True
        
    except Exception as e:
        print(f"[FAIL] Configuration loading test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("=" * 60)
    print("bountybot v2.0.0 Installation and Functionality Test")
    print("=" * 60)
    
    tests = [
        ("Import Test", test_imports),
        ("Basic Functionality Test", test_basic_functionality),
        ("CLI Help Test", test_cli_help),
        ("Example Parsing Test", test_example_parsing),
        ("Configuration Loading Test", test_config_loading),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        print("-" * 40)
        
        if test_func():
            passed += 1
        else:
            print(f"FAILED: {test_name}")
    
    print("\n" + "=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")
    print("=" * 60)
    
    if passed == total:
        print("All tests passed! bountybot is ready to use.")
        print("\nNext steps:")
        print("1. Set your API key: export ANTHROPIC_API_KEY='your-key-here'")
        print("2. Try an example: python3 -m bountybot.cli examples/sql_injection_report.json")
        return True
    else:
        print("Some tests failed. Please check the errors above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
