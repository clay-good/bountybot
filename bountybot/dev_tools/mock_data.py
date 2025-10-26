"""
Mock data generators for testing and development.

Provides realistic mock data for reports, HTTP requests, and validation results.
"""

import random
import string
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from bountybot.models import Report, Verdict


class MockDataGenerator:
    """
    Generate mock data for testing and development.
    
    Features:
    - Generate realistic bug bounty reports
    - Generate HTTP requests with various vulnerabilities
    - Generate validation results
    - Customizable data patterns
    """
    
    # Vulnerability types
    VULNERABILITY_TYPES = [
        'SQL Injection',
        'Cross-Site Scripting (XSS)',
        'Server-Side Request Forgery (SSRF)',
        'Remote Code Execution (RCE)',
        'Authentication Bypass',
        'Authorization Bypass',
        'Insecure Direct Object Reference (IDOR)',
        'Cross-Site Request Forgery (CSRF)',
        'XML External Entity (XXE)',
        'Server-Side Template Injection (SSTI)',
        'JWT Vulnerabilities',
        'Path Traversal',
        'Open Redirect',
        'Information Disclosure',
        'Broken Access Control'
    ]
    
    # Severity levels
    SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational']
    
    # Platforms
    PLATFORMS = ['HackerOne', 'Bugcrowd', 'Synack', 'YesWeHack', 'Intigriti']
    
    # Sample domains
    DOMAINS = [
        'example.com',
        'testapp.io',
        'demo-site.net',
        'vulnerable-app.com',
        'test-target.org'
    ]
    
    @staticmethod
    def generate_report(
        vulnerability_type: Optional[str] = None,
        severity: Optional[str] = None,
        platform: Optional[str] = None,
        include_http_requests: bool = True,
        include_steps: bool = True,
        include_impact: bool = True
    ) -> Dict[str, Any]:
        """
        Generate mock bug bounty report.
        
        Args:
            vulnerability_type: Specific vulnerability type
            severity: Specific severity level
            platform: Specific platform
            include_http_requests: Include HTTP requests in description
            include_steps: Include steps to reproduce
            include_impact: Include impact description
            
        Returns:
            Mock report dictionary
        """
        vuln_type = vulnerability_type or random.choice(MockDataGenerator.VULNERABILITY_TYPES)
        sev = severity or random.choice(MockDataGenerator.SEVERITIES)
        plat = platform or random.choice(MockDataGenerator.PLATFORMS)
        domain = random.choice(MockDataGenerator.DOMAINS)
        
        report_id = f"MOCK-{random.randint(100000, 999999)}"
        
        # Generate description
        description_parts = [
            f"I discovered a {vuln_type} vulnerability in the application at https://{domain}.",
            f"This vulnerability allows an attacker to compromise the security of the application."
        ]
        
        if include_http_requests:
            http_request = MockDataGenerator._generate_http_request(vuln_type, domain)
            description_parts.append(f"\n\nVulnerable Request:\n```\n{http_request}\n```")
        
        description = "\n\n".join(description_parts)
        
        # Generate steps to reproduce
        steps = None
        if include_steps:
            steps = MockDataGenerator._generate_steps(vuln_type, domain)
        
        # Generate impact
        impact = None
        if include_impact:
            impact = MockDataGenerator._generate_impact(vuln_type, sev)
        
        return {
            'id': report_id,
            'title': f"{vuln_type} in {domain}",
            'description': description,
            'vulnerability_type': vuln_type,
            'severity': sev,
            'platform': plat,
            'researcher_name': MockDataGenerator._generate_researcher_name(),
            'submitted_at': (datetime.utcnow() - timedelta(days=random.randint(1, 30))).isoformat(),
            'steps_to_reproduce': steps,
            'impact': impact,
            'metadata': {
                'bounty_amount': random.randint(100, 10000) if sev in ['Critical', 'High'] else 0,
                'program': f"{domain.split('.')[0].title()} Bug Bounty Program"
            }
        }
    
    @staticmethod
    def _generate_http_request(vuln_type: str, domain: str) -> str:
        """Generate HTTP request based on vulnerability type."""
        if vuln_type == 'SQL Injection':
            return f"""POST /api/users HTTP/1.1
Host: {domain}
Content-Type: application/json

{{"username": "admin' OR '1'='1", "password": "test"}}"""
        
        elif vuln_type == 'Cross-Site Scripting (XSS)':
            return f"""GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1
Host: {domain}"""
        
        elif vuln_type == 'Server-Side Request Forgery (SSRF)':
            return f"""POST /api/fetch HTTP/1.1
Host: {domain}
Content-Type: application/json

{{"url": "http://169.254.169.254/latest/meta-data/"}}"""
        
        elif vuln_type == 'Remote Code Execution (RCE)':
            return f"""POST /api/execute HTTP/1.1
Host: {domain}
Content-Type: application/json

{{"command": "cat /etc/passwd"}}"""
        
        elif vuln_type == 'Authentication Bypass':
            return f"""GET /admin/dashboard HTTP/1.1
Host: {domain}
X-Forwarded-For: 127.0.0.1"""
        
        else:
            return f"""GET /api/endpoint HTTP/1.1
Host: {domain}"""
    
    @staticmethod
    def _generate_steps(vuln_type: str, domain: str) -> str:
        """Generate steps to reproduce."""
        return f"""1. Navigate to https://{domain}
2. Open browser developer tools
3. Send the malicious request shown above
4. Observe the vulnerability being exploited
5. Verify the security impact"""
    
    @staticmethod
    def _generate_impact(vuln_type: str, severity: str) -> str:
        """Generate impact description."""
        impacts = {
            'Critical': "This vulnerability allows complete compromise of the application and underlying infrastructure.",
            'High': "This vulnerability allows unauthorized access to sensitive data and functionality.",
            'Medium': "This vulnerability allows limited unauthorized access or information disclosure.",
            'Low': "This vulnerability has minimal security impact but should be addressed.",
            'Informational': "This is a security best practice issue with no immediate exploitability."
        }
        return impacts.get(severity, "Security impact varies based on exploitation.")
    
    @staticmethod
    def _generate_researcher_name() -> str:
        """Generate researcher name."""
        first_names = ['Alex', 'Jordan', 'Taylor', 'Morgan', 'Casey', 'Riley', 'Avery', 'Quinn']
        last_names = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis']
        return f"{random.choice(first_names)} {random.choice(last_names)}"
    
    @staticmethod
    def generate_http_request(
        method: str = 'GET',
        url: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate mock HTTP request.
        
        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            body: Request body
            
        Returns:
            Mock HTTP request dictionary
        """
        domain = random.choice(MockDataGenerator.DOMAINS)
        url = url or f"https://{domain}/api/endpoint"
        
        default_headers = {
            'Host': domain,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        if headers:
            default_headers.update(headers)
        
        return {
            'method': method,
            'url': url,
            'headers': default_headers,
            'body': body
        }
    
    @staticmethod
    def generate_validation_result(
        verdict: Optional[str] = None,
        confidence: Optional[float] = None,
        severity: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate mock validation result.
        
        Args:
            verdict: Validation verdict (VALID, INVALID, UNCERTAIN)
            confidence: Confidence score (0.0-1.0)
            severity: Severity level
            
        Returns:
            Mock validation result dictionary
        """
        verdict = verdict or random.choice(['VALID', 'INVALID', 'UNCERTAIN'])
        confidence = confidence if confidence is not None else random.uniform(0.7, 0.99)
        severity = severity or random.choice(MockDataGenerator.SEVERITIES)
        
        reasoning_templates = {
            'VALID': "The report demonstrates a genuine security vulnerability with clear exploitation steps and impact.",
            'INVALID': "The report does not demonstrate a valid security vulnerability. The described behavior is expected.",
            'UNCERTAIN': "The report requires additional investigation to determine if it represents a valid security vulnerability."
        }
        
        return {
            'verdict': verdict,
            'confidence': confidence,
            'severity': severity,
            'reasoning': reasoning_templates[verdict],
            'recommendations': [
                'Review the security implications',
                'Verify the exploitation steps',
                'Assess the business impact'
            ],
            'metadata': {
                'quality_score': random.uniform(0.6, 1.0),
                'plausibility_score': random.uniform(0.6, 1.0),
                'validation_time': random.uniform(5.0, 30.0)
            }
        }
    
    @staticmethod
    def generate_batch_reports(count: int = 10) -> List[Dict[str, Any]]:
        """
        Generate batch of mock reports.
        
        Args:
            count: Number of reports to generate
            
        Returns:
            List of mock reports
        """
        return [MockDataGenerator.generate_report() for _ in range(count)]
    
    @staticmethod
    def generate_test_suite() -> Dict[str, Any]:
        """
        Generate complete test suite with various scenarios.
        
        Returns:
            Test suite dictionary with multiple scenarios
        """
        return {
            'valid_reports': [
                MockDataGenerator.generate_report(vuln_type, 'High')
                for vuln_type in ['SQL Injection', 'XSS', 'SSRF']
            ],
            'invalid_reports': [
                MockDataGenerator.generate_report(include_http_requests=False)
                for _ in range(3)
            ],
            'edge_cases': [
                MockDataGenerator.generate_report(include_steps=False),
                MockDataGenerator.generate_report(include_impact=False),
                MockDataGenerator.generate_report(severity='Informational')
            ]
        }

