import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from bountybot.extractors.http_extractor import HTTPRequest

logger = logging.getLogger(__name__)


@dataclass
class ProofOfConcept:
    """
    Represents a generated proof-of-concept exploit.
    """
    vulnerability_type: str
    title: str
    description: str
    
    # Code in different formats
    curl_command: Optional[str] = None
    python_code: Optional[str] = None
    javascript_code: Optional[str] = None
    raw_http: Optional[str] = None
    
    # Metadata
    severity: Optional[str] = None
    prerequisites: List[str] = field(default_factory=list)
    expected_result: Optional[str] = None
    safety_notes: List[str] = field(default_factory=list)
    http_requests: List[HTTPRequest] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'vulnerability_type': self.vulnerability_type,
            'title': self.title,
            'description': self.description,
            'curl_command': self.curl_command,
            'python_code': self.python_code,
            'javascript_code': self.javascript_code,
            'raw_http': self.raw_http,
            'severity': self.severity,
            'prerequisites': self.prerequisites,
            'expected_result': self.expected_result,
            'safety_notes': self.safety_notes,
            'http_requests': [req.to_dict() for req in self.http_requests],
        }

    def to_markdown_bluf(self) -> str:
        """Format PoC as Markdown with BLUF (Bottom Line Up Front) style."""
        md = []

        # BLUF Header
        md.append("# PROOF OF CONCEPT (PoC)")
        md.append("")
        md.append("## BOTTOM LINE UP FRONT (BLUF)")
        md.append("")
        md.append(f"**Vulnerability:** {self.vulnerability_type}")
        md.append(f"**Severity:** {self.severity or 'UNKNOWN'}")
        md.append("")
        md.append(f"**What This PoC Demonstrates:** {self.title}")
        md.append("")
        md.append("**Expected Result:**")
        md.append(self.expected_result or "See description below")
        md.append("")
        md.append("---")
        md.append("")

        # Safety Warning
        md.append("## ⚠️ SAFETY AND LEGAL NOTICE")
        md.append("")
        md.append("**CRITICAL:** Only execute this PoC on systems you own or have explicit written permission to test.")
        md.append("")
        if self.safety_notes:
            for note in self.safety_notes:
                md.append(f"- {note}")
        md.append("- Unauthorized testing may be illegal and unethical")
        md.append("- Always follow responsible disclosure practices")
        md.append("- Test in isolated environments when possible")
        md.append("")
        md.append("---")
        md.append("")

        # Description
        md.append("## DESCRIPTION")
        md.append("")
        md.append(self.description)
        md.append("")

        # Prerequisites
        if self.prerequisites:
            md.append("## PREREQUISITES")
            md.append("")
            for i, prereq in enumerate(self.prerequisites, 1):
                md.append(f"{i}. {prereq}")
            md.append("")

        # Exploitation Steps
        md.append("## EXPLOITATION STEPS")
        md.append("")

        if self.curl_command:
            md.append("### Option 1: Using cURL")
            md.append("")
            md.append("```bash")
            md.append(self.curl_command)
            md.append("```")
            md.append("")

        if self.python_code:
            md.append("### Option 2: Using Python")
            md.append("")
            md.append("```python")
            md.append(self.python_code)
            md.append("```")
            md.append("")

        if self.javascript_code:
            md.append("### Option 3: Using JavaScript")
            md.append("")
            md.append("```javascript")
            md.append(self.javascript_code)
            md.append("```")
            md.append("")

        if self.raw_http:
            md.append("### Raw HTTP Request")
            md.append("")
            md.append("```http")
            md.append(self.raw_http)
            md.append("```")
            md.append("")

        # Expected Result
        md.append("## EXPECTED RESULT")
        md.append("")
        md.append(self.expected_result or "See description above")
        md.append("")

        # Remediation
        md.append("## REMEDIATION GUIDANCE")
        md.append("")
        md.append("This PoC demonstrates a valid security vulnerability. Immediate remediation is required:")
        md.append("")
        md.append("1. Review the vulnerable code/configuration")
        md.append("2. Implement proper input validation and sanitization")
        md.append("3. Apply security best practices for this vulnerability type")
        md.append("4. Test the fix thoroughly")
        md.append("5. Deploy to production following change management procedures")
        md.append("")

        return "\n".join(md)


class PoCGenerator:
    """
    Generates proof-of-concept exploits for validated vulnerabilities.
    """
    
    def __init__(self, ai_provider=None):
        """
        Initialize PoC generator.
        
        Args:
            ai_provider: Optional AI provider for intelligent PoC generation
        """
        self.ai_provider = ai_provider
    
    def generate(self, report, http_requests: List[HTTPRequest], 
                 validation_result=None) -> ProofOfConcept:
        """
        Generate a proof-of-concept exploit.
        
        Args:
            report: Bug bounty report
            http_requests: Extracted HTTP requests
            validation_result: Optional validation result for context
            
        Returns:
            Generated ProofOfConcept
        """
        vuln_type = report.vulnerability_type or "Unknown"
        
        # Use AI to generate intelligent PoC if available
        if self.ai_provider and len(http_requests) > 0:
            return self._generate_with_ai(report, http_requests, validation_result)
        
        # Otherwise use template-based generation
        return self._generate_template_based(report, http_requests)
    
    def _generate_with_ai(self, report, http_requests: List[HTTPRequest],
                          validation_result) -> ProofOfConcept:
        """Generate PoC using AI."""
        logger.info("Generating PoC with AI assistance")
        
        # Prepare context for AI
        context = self._prepare_context(report, http_requests, validation_result)
        
        system_prompt = """You are a security expert creating proof-of-concept exploits for validated vulnerabilities.

Your task is to generate a safe, working PoC that demonstrates the vulnerability without causing harm.

Requirements:
1. Generate working code in multiple formats (curl, Python, JavaScript)
2. Include clear prerequisites and setup instructions
3. Describe the expected result
4. Add safety notes and warnings
5. Make the PoC as simple and clear as possible
6. Ensure the PoC is safe to run in a test environment

Respond with valid JSON in this format:
{
  "title": "Clear PoC title",
  "description": "Detailed description of what the PoC does",
  "curl_command": "Complete curl command",
  "python_code": "Complete Python script",
  "javascript_code": "Complete JavaScript code (if applicable)",
  "raw_http": "Raw HTTP request",
  "prerequisites": ["prerequisite1", "prerequisite2"],
  "expected_result": "What should happen when the PoC is executed",
  "safety_notes": ["safety note 1", "safety note 2"]
}"""
        
        user_prompt = f"""Generate a proof-of-concept exploit for this vulnerability:

{context}

Create a safe, working PoC that clearly demonstrates the vulnerability."""
        
        try:
            response = self.ai_provider.complete_with_json(system_prompt, user_prompt, max_tokens=3000)
            data = response.get('parsed')
            
            if data:
                poc = ProofOfConcept(
                    vulnerability_type=report.vulnerability_type or "Unknown",
                    title=data.get('title', f"PoC for {report.title}"),
                    description=data.get('description', ''),
                    curl_command=data.get('curl_command'),
                    python_code=data.get('python_code'),
                    javascript_code=data.get('javascript_code'),
                    raw_http=data.get('raw_http'),
                    severity=report.severity.value if report.severity else None,
                    prerequisites=data.get('prerequisites', []),
                    expected_result=data.get('expected_result'),
                    safety_notes=data.get('safety_notes', []),
                    http_requests=http_requests,
                )
                
                logger.info("Successfully generated AI-powered PoC")
                return poc
            else:
                logger.warning("AI failed to generate PoC, falling back to template")
                return self._generate_template_based(report, http_requests)
                
        except Exception as e:
            logger.error(f"Error generating AI PoC: {e}")
            return self._generate_template_based(report, http_requests)
    
    def _generate_template_based(self, report, http_requests: List[HTTPRequest]) -> ProofOfConcept:
        """Generate PoC using templates."""
        logger.info("Generating template-based PoC")
        
        vuln_type = (report.vulnerability_type or "Unknown").lower()
        
        # Select the best HTTP request
        primary_request = http_requests[0] if http_requests else None
        
        if not primary_request:
            return self._generate_minimal_poc(report)
        
        # Generate based on vulnerability type
        if 'sql' in vuln_type or 'injection' in vuln_type:
            return self._generate_sql_injection_poc(report, primary_request)
        elif 'xss' in vuln_type or 'cross-site scripting' in vuln_type:
            return self._generate_xss_poc(report, primary_request)
        elif 'csrf' in vuln_type:
            return self._generate_csrf_poc(report, primary_request)
        elif 'ssrf' in vuln_type:
            return self._generate_ssrf_poc(report, primary_request)
        else:
            return self._generate_generic_poc(report, primary_request)
    
    def _generate_sql_injection_poc(self, report, request: HTTPRequest) -> ProofOfConcept:
        """Generate SQL injection PoC."""
        curl_cmd = request.to_curl()
        python_code = request.to_python_requests()
        
        description = f"""This PoC demonstrates SQL injection in {request.url}.
The vulnerability allows an attacker to manipulate SQL queries and potentially:
- Extract sensitive data from the database
- Bypass authentication
- Modify or delete data

The payload is injected via: {', '.join(request.payload_locations) if request.payload_locations else 'query parameters'}"""
        
        safety_notes = [
            "Only test on systems you have permission to test",
            "Use a test database, not production",
            "This PoC is for demonstration purposes only",
            "Monitor database logs during testing"
        ]
        
        prerequisites = [
            "Valid authentication credentials (if required)",
            "Network access to the target",
            "Python 3.x with requests library (for Python PoC)"
        ]
        
        expected_result = "The response should contain data that wouldn't normally be accessible, or show SQL error messages revealing database structure."
        
        return ProofOfConcept(
            vulnerability_type="SQL Injection",
            title=f"SQL Injection PoC - {report.title}",
            description=description,
            curl_command=curl_cmd,
            python_code=python_code,
            raw_http=request.raw_request,
            severity=report.severity.value if report.severity else "High",
            prerequisites=prerequisites,
            expected_result=expected_result,
            safety_notes=safety_notes,
            http_requests=[request],
        )
    
    def _generate_xss_poc(self, report, request: HTTPRequest) -> ProofOfConcept:
        """Generate XSS PoC."""
        curl_cmd = request.to_curl()
        python_code = request.to_python_requests()
        
        # Generate JavaScript PoC for XSS
        js_code = f"""// XSS Proof of Concept
// This demonstrates the XSS vulnerability

// Method 1: Direct injection via URL
window.location = '{request.url}';

// Method 2: Fetch API
fetch('{request.url}', {{
    method: '{request.method}',
    headers: {{{', '.join([f"'{k}': '{v}'" for k, v in request.headers.items()])}}},
    {f"body: '{request.body}'" if request.body else ''}
}})
.then(response => response.text())
.then(html => {{
    // Check if the payload is reflected in the response
    console.log('Response:', html);
    if (html.includes('<script>')) {{
        console.log('XSS payload successfully injected!');
    }}
}});"""
        
        description = f"""This PoC demonstrates Cross-Site Scripting (XSS) in {request.url}.
The vulnerability allows an attacker to inject malicious JavaScript that executes in victims' browsers.

Potential impact:
- Session hijacking
- Credential theft
- Defacement
- Phishing attacks

The payload is injected via: {', '.join(request.payload_locations) if request.payload_locations else 'user input'}"""
        
        safety_notes = [
            "Only test on systems you have permission to test",
            "Use harmless payloads like alert() for testing",
            "Do not use this to attack real users",
            "Test in an isolated browser session"
        ]
        
        prerequisites = [
            "Network access to the target",
            "A modern web browser",
            "Python 3.x with requests library (for Python PoC)"
        ]
        
        expected_result = "The JavaScript payload should execute in the browser, typically showing an alert box or logging to console."
        
        return ProofOfConcept(
            vulnerability_type="Cross-Site Scripting (XSS)",
            title=f"XSS PoC - {report.title}",
            description=description,
            curl_command=curl_cmd,
            python_code=python_code,
            javascript_code=js_code,
            raw_http=request.raw_request,
            severity=report.severity.value if report.severity else "Medium",
            prerequisites=prerequisites,
            expected_result=expected_result,
            safety_notes=safety_notes,
            http_requests=[request],
        )
    
    def _generate_csrf_poc(self, report, request: HTTPRequest) -> ProofOfConcept:
        """Generate CSRF PoC."""
        # Generate HTML form for CSRF
        html_poc = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - {report.title}</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>This page demonstrates a CSRF vulnerability.</p>
    
    <form id="csrf-form" action="{request.url}" method="{request.method}">
"""
        
        # Add form fields from request body or query params
        if request.body:
            for param in request.body.split('&'):
                if '=' in param:
                    name, value = param.split('=', 1)
                    html_poc += f'        <input type="hidden" name="{name}" value="{value}" />\n'
        
        html_poc += """        <input type="submit" value="Click here" />
    </form>
    
    <script>
        // Auto-submit the form
        // document.getElementById('csrf-form').submit();
    </script>
</body>
</html>"""
        
        description = f"""This PoC demonstrates Cross-Site Request Forgery (CSRF) in {request.url}.
The vulnerability allows an attacker to perform actions on behalf of authenticated users without their consent.

The HTML page contains a form that submits a request to the vulnerable endpoint."""
        
        return ProofOfConcept(
            vulnerability_type="Cross-Site Request Forgery (CSRF)",
            title=f"CSRF PoC - {report.title}",
            description=description,
            curl_command=request.to_curl(),
            python_code=request.to_python_requests(),
            javascript_code=html_poc,
            raw_http=request.raw_request,
            severity=report.severity.value if report.severity else "Medium",
            prerequisites=["Victim must be authenticated", "Victim must visit the malicious page"],
            expected_result="The action should be performed without the user's explicit consent.",
            safety_notes=["Only test with your own authenticated session", "Do not distribute the PoC page"],
            http_requests=[request],
        )

    def _generate_ssrf_poc(self, report, request: HTTPRequest) -> ProofOfConcept:
        """Generate SSRF PoC."""
        description = f"""This PoC demonstrates Server-Side Request Forgery (SSRF) in {request.url}.
The vulnerability allows an attacker to make the server perform requests to arbitrary URLs.

Potential impact:
- Access to internal services
- Port scanning
- Cloud metadata access (AWS, GCP, Azure)
- Bypass firewall restrictions"""

        # Generate Python code with SSRF payloads
        python_code = f"""{request.to_python_requests()}

# Additional SSRF test payloads:
# 1. Internal network scan
# response = requests.{request.method.lower()}('{request.url}', params={{'url': 'http://127.0.0.1:8080'}})

# 2. Cloud metadata (AWS)
# response = requests.{request.method.lower()}('{request.url}', params={{'url': 'http://169.254.169.254/latest/meta-data/'}})

# 3. File protocol (if supported)
# response = requests.{request.method.lower()}('{request.url}', params={{'url': 'file:///etc/passwd'}})
"""

        return ProofOfConcept(
            vulnerability_type="Server-Side Request Forgery (SSRF)",
            title=f"SSRF PoC - {report.title}",
            description=description,
            curl_command=request.to_curl(),
            python_code=python_code,
            raw_http=request.raw_request,
            severity=report.severity.value if report.severity else "High",
            prerequisites=["Network access to the target", "Understanding of internal network topology"],
            expected_result="The server should make a request to the specified URL and return the response.",
            safety_notes=[
                "Only test on systems you have permission to test",
                "Do not scan production internal networks",
                "Be careful with cloud metadata endpoints"
            ],
            http_requests=[request],
        )

    def _generate_generic_poc(self, report, request: HTTPRequest) -> ProofOfConcept:
        """Generate generic PoC."""
        description = f"""This PoC demonstrates the vulnerability in {request.url}.

Vulnerability Type: {report.vulnerability_type or 'Unknown'}

{report.impact_description or 'See report for impact details.'}"""

        return ProofOfConcept(
            vulnerability_type=report.vulnerability_type or "Unknown",
            title=f"PoC - {report.title}",
            description=description,
            curl_command=request.to_curl(),
            python_code=request.to_python_requests(),
            raw_http=request.raw_request,
            severity=report.severity.value if report.severity else "Medium",
            prerequisites=["Network access to the target", "Valid credentials (if required)"],
            expected_result="See report for expected behavior.",
            safety_notes=["Only test on systems you have permission to test"],
            http_requests=[request],
        )

    def _generate_minimal_poc(self, report) -> ProofOfConcept:
        """Generate minimal PoC when no HTTP requests are available."""
        description = f"""Proof of concept for: {report.title}

{report.impact_description or ''}

Original PoC from report:
{report.proof_of_concept or 'No PoC provided in report'}"""

        return ProofOfConcept(
            vulnerability_type=report.vulnerability_type or "Unknown",
            title=f"PoC - {report.title}",
            description=description,
            severity=report.severity.value if report.severity else "Unknown",
            prerequisites=["See original report for details"],
            expected_result="See original report for expected behavior.",
            safety_notes=["Only test on systems you have permission to test"],
        )

    def _prepare_context(self, report, http_requests: List[HTTPRequest],
                        validation_result) -> str:
        """Prepare context for AI PoC generation."""
        context_parts = [
            f"Vulnerability: {report.title}",
            f"Type: {report.vulnerability_type or 'Unknown'}",
            f"Severity: {report.severity.value if report.severity else 'Unknown'}",
            "",
            "Description:",
            report.impact_description or "No description provided",
            "",
        ]

        if report.reproduction_steps:
            context_parts.append("Reproduction Steps:")
            for i, step in enumerate(report.reproduction_steps, 1):
                context_parts.append(f"{i}. {step}")
            context_parts.append("")

        if http_requests:
            context_parts.append("Extracted HTTP Requests:")
            for i, req in enumerate(http_requests, 1):
                context_parts.append(f"\nRequest {i}:")
                context_parts.append(f"  Method: {req.method}")
                context_parts.append(f"  URL: {req.url}")
                if req.headers:
                    context_parts.append(f"  Headers: {req.headers}")
                if req.body:
                    context_parts.append(f"  Body: {req.body}")
                if req.payload_locations:
                    context_parts.append(f"  Payload Locations: {', '.join(req.payload_locations)}")
            context_parts.append("")

        if validation_result and validation_result.key_findings:
            context_parts.append("Key Findings from Validation:")
            for finding in validation_result.key_findings:
                context_parts.append(f"- {finding}")
            context_parts.append("")

        return "\n".join(context_parts)

