import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


@dataclass
class HTTPRequest:
    """
    Represents an extracted HTTP request from a bug bounty report.
    """
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    query_params: Dict[str, List[str]] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)

    # Metadata
    raw_request: Optional[str] = None
    extraction_confidence: float = 0.0
    extraction_method: Optional[str] = None
    payload_locations: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Parse query params from URL if not already set."""
        if not self.query_params and self.url:
            parsed = urlparse(self.url)
            if parsed.query:
                self.query_params = parse_qs(parsed.query)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'method': self.method,
            'url': self.url,
            'headers': self.headers,
            'body': self.body,
            'query_params': self.query_params,
            'cookies': self.cookies,
            'raw_request': self.raw_request,
            'extraction_confidence': self.extraction_confidence,
            'extraction_method': self.extraction_method,
            'payload_locations': self.payload_locations,
        }
    
    def to_curl(self) -> str:
        """Convert to curl command."""
        parts = ['curl', '-X', self.method]
        
        # Add headers
        for key, value in self.headers.items():
            parts.append(f'-H "{key}: {value}"')
        
        # Add cookies
        if self.cookies:
            cookie_str = '; '.join([f'{k}={v}' for k, v in self.cookies.items()])
            parts.append(f'-H "Cookie: {cookie_str}"')
        
        # Add body
        if self.body:
            parts.append(f'-d \'{self.body}\'')
        
        # Add URL
        parts.append(f'"{self.url}"')
        
        return ' '.join(parts)
    
    def to_python_requests(self) -> str:
        """Convert to Python requests code."""
        lines = ['import requests', '']
        
        # Headers
        if self.headers or self.cookies:
            lines.append('headers = {')
            for key, value in self.headers.items():
                lines.append(f'    "{key}": "{value}",')
            lines.append('}')
            lines.append('')
        
        # Cookies
        if self.cookies:
            lines.append('cookies = {')
            for key, value in self.cookies.items():
                lines.append(f'    "{key}": "{value}",')
            lines.append('}')
            lines.append('')
        
        # Request
        method_lower = self.method.lower()
        args = [f'"{self.url}"']
        
        if self.headers or self.cookies:
            args.append('headers=headers')
        if self.cookies:
            args.append('cookies=cookies')
        if self.body:
            if self.headers.get('Content-Type', '').startswith('application/json'):
                args.append(f'json={self.body}')
            else:
                args.append(f'data=\'{self.body}\'')
        
        lines.append(f'response = requests.{method_lower}({", ".join(args)})')
        lines.append('print(response.status_code)')
        lines.append('print(response.text)')
        
        return '\n'.join(lines)


class HTTPRequestExtractor:
    """
    Extracts HTTP requests from bug bounty reports in various formats.
    """
    
    # Patterns for different HTTP request formats
    RAW_HTTP_PATTERN = re.compile(
        r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP/[\d.]+\r?\n'
        r'((?:[^\r\n]+:\s*[^\r\n]+\r?\n)*)'
        r'\r?\n'
        r'(.*)',
        re.DOTALL | re.IGNORECASE
    )
    
    CURL_PATTERN = re.compile(
        r'curl\s+(?:-X\s+)?([A-Z]+)?\s*'
        r'(?:(?:-H|--header)\s+["\']([^"\']+)["\']\s*)*'
        r'(?:(?:-d|--data|--data-raw)\s+["\']([^"\']+)["\']\s*)?'
        r'["\']?([^"\'\s]+)["\']?',
        re.IGNORECASE | re.DOTALL
    )
    
    def __init__(self):
        """Initialize HTTP request extractor."""
        pass
    
    def extract_from_report(self, report) -> List[HTTPRequest]:
        """
        Extract all HTTP requests from a bug bounty report.
        
        Args:
            report: Report object
            
        Returns:
            List of extracted HTTP requests
        """
        requests = []
        
        # Extract from proof of concept
        if report.proof_of_concept:
            requests.extend(self._extract_from_text(report.proof_of_concept))
        
        # Extract from reproduction steps
        if report.reproduction_steps:
            for step in report.reproduction_steps:
                requests.extend(self._extract_from_text(step))
        
        # Extract from raw content
        if report.raw_content:
            requests.extend(self._extract_from_text(report.raw_content))
        
        # Deduplicate requests
        unique_requests = self._deduplicate_requests(requests)
        
        logger.info(f"Extracted {len(unique_requests)} unique HTTP requests from report")
        return unique_requests
    
    def _extract_from_text(self, text: str) -> List[HTTPRequest]:
        """Extract HTTP requests from text content."""
        requests = []
        
        # Try raw HTTP format
        requests.extend(self._extract_raw_http(text))
        
        # Try curl commands
        requests.extend(self._extract_curl(text))
        
        # Try URL patterns
        requests.extend(self._extract_urls(text))
        
        return requests
    
    def _extract_raw_http(self, text: str) -> List[HTTPRequest]:
        """Extract raw HTTP requests."""
        requests = []
        
        for match in self.RAW_HTTP_PATTERN.finditer(text):
            method = match.group(1).upper()
            path = match.group(2)
            headers_text = match.group(3)
            body = match.group(4).strip() if match.group(4) else None
            
            # Parse headers
            headers = {}
            cookies = {}
            host = None
            
            for line in headers_text.split('\n'):
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key.lower() == 'cookie':
                        # Parse cookies
                        for cookie in value.split(';'):
                            cookie = cookie.strip()
                            if '=' in cookie:
                                ck, cv = cookie.split('=', 1)
                                cookies[ck.strip()] = cv.strip()
                    elif key.lower() == 'host':
                        host = value
                    else:
                        headers[key] = value
            
            # Construct full URL
            if host:
                # Default to HTTPS for security
                scheme = 'https'
                url = f"{scheme}://{host}{path}"
            else:
                url = path
            
            # Parse query parameters
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            request = HTTPRequest(
                method=method,
                url=url,
                headers=headers,
                body=body,
                query_params=query_params,
                cookies=cookies,
                raw_request=match.group(0),
                extraction_confidence=0.95,
                extraction_method='raw_http'
            )
            
            # Identify payload locations
            request.payload_locations = self._identify_payload_locations(request)
            
            requests.append(request)
            logger.debug(f"Extracted raw HTTP request: {method} {url}")
        
        return requests
    
    def _extract_curl(self, text: str) -> List[HTTPRequest]:
        """Extract curl commands."""
        requests = []
        
        # Find all curl commands
        curl_matches = re.finditer(r'curl\s+[^\n]+(?:\\\n[^\n]+)*', text, re.IGNORECASE)
        
        for match in curl_matches:
            curl_cmd = match.group(0)
            
            try:
                request = self._parse_curl_command(curl_cmd)
                if request:
                    requests.append(request)
                    logger.debug(f"Extracted curl request: {request.method} {request.url}")
            except Exception as e:
                logger.warning(f"Failed to parse curl command: {e}")
        
        return requests
    
    def _parse_curl_command(self, curl_cmd: str) -> Optional[HTTPRequest]:
        """Parse a curl command into HTTPRequest."""
        # Remove line continuations
        curl_cmd = curl_cmd.replace('\\\n', ' ').replace('\\', '')
        
        # Extract method
        method_match = re.search(r'-X\s+([A-Z]+)', curl_cmd, re.IGNORECASE)
        method = method_match.group(1).upper() if method_match else 'GET'
        
        # Extract URL
        url_match = re.search(r'["\']?(https?://[^"\'\s]+)["\']?', curl_cmd)
        if not url_match:
            return None
        url = url_match.group(1)
        
        # Extract headers
        headers = {}
        header_matches = re.finditer(r'(?:-H|--header)\s+["\']([^:]+):\s*([^"\']+)["\']', curl_cmd)
        for match in header_matches:
            headers[match.group(1)] = match.group(2)
        
        # Extract cookies
        cookies = {}
        cookie_match = re.search(r'(?:-b|--cookie)\s+["\']([^"\']+)["\']', curl_cmd)
        if cookie_match:
            for cookie in cookie_match.group(1).split(';'):
                cookie = cookie.strip()
                if '=' in cookie:
                    ck, cv = cookie.split('=', 1)
                    cookies[ck.strip()] = cv.strip()
        
        # Extract body - handle both quoted and unquoted
        body = None
        # Try single quotes first
        body_match = re.search(r"(?:-d|--data|--data-raw)\s+'([^']+)'", curl_cmd, re.DOTALL)
        if not body_match:
            # Try double quotes
            body_match = re.search(r'(?:-d|--data|--data-raw)\s+"([^"]+)"', curl_cmd, re.DOTALL)
        if body_match:
            body = body_match.group(1)
        
        # Parse query parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        request = HTTPRequest(
            method=method,
            url=url,
            headers=headers,
            body=body,
            query_params=query_params,
            cookies=cookies,
            raw_request=curl_cmd,
            extraction_confidence=0.90,
            extraction_method='curl'
        )
        
        # Identify payload locations
        request.payload_locations = self._identify_payload_locations(request)

        return request

    def _extract_urls(self, text: str) -> List[HTTPRequest]:
        """Extract simple URLs and convert to GET requests."""
        requests = []

        # Find URLs
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')

        for match in url_pattern.finditer(text):
            url = match.group(0)

            # Parse query parameters
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            request = HTTPRequest(
                method='GET',
                url=url,
                query_params=query_params,
                raw_request=url,
                extraction_confidence=0.70,
                extraction_method='url_pattern'
            )

            # Identify payload locations
            request.payload_locations = self._identify_payload_locations(request)

            requests.append(request)
            logger.debug(f"Extracted URL: {url}")

        return requests

    def _identify_payload_locations(self, request: HTTPRequest) -> List[str]:
        """Identify where payloads might be located in the request."""
        locations = []

        # Check query parameters for suspicious values
        for param, values in request.query_params.items():
            for value in values:
                if self._looks_like_payload(value):
                    locations.append(f"query_param:{param}")

        # Check body for payloads
        if request.body and self._looks_like_payload(request.body):
            locations.append("body")

        # Check headers for payloads
        for header, value in request.headers.items():
            if self._looks_like_payload(value):
                locations.append(f"header:{header}")

        # Check cookies for payloads
        for cookie, value in request.cookies.items():
            if self._looks_like_payload(value):
                locations.append(f"cookie:{cookie}")

        return locations

    def _looks_like_payload(self, value: str) -> bool:
        """Check if a value looks like an attack payload."""
        if not value:
            return False

        # Common payload patterns
        payload_indicators = [
            r'<script',
            r'javascript:',
            r'onerror=',
            r'onload=',
            r'\'.*OR.*\'',
            r'".*OR.*"',
            r'UNION\s+SELECT',
            r'\.\./\.\.',
            r'%00',
            r'%0d%0a',
            r'{{.*}}',
            r'\$\{.*\}',
            r'eval\(',
            r'exec\(',
            r'system\(',
            r'cmd=',
            r'command=',
            r';\s*(cat|ls|whoami|id|pwd)',  # Command injection
            r'\|\s*(cat|ls|whoami|id|pwd)',  # Pipe command injection
        ]

        value_lower = value.lower()
        for pattern in payload_indicators:
            if re.search(pattern, value_lower, re.IGNORECASE):
                return True

        return False

    def _deduplicate_requests(self, requests: List[HTTPRequest]) -> List[HTTPRequest]:
        """Remove duplicate requests."""
        seen = set()
        unique = []

        for request in requests:
            # Create a signature for the request
            signature = f"{request.method}:{request.url}:{request.body}"

            if signature not in seen:
                seen.add(signature)
                unique.append(request)

        return unique

    def validate_request(self, request: HTTPRequest) -> tuple[bool, List[str]]:
        """
        Validate an HTTP request for completeness and correctness.

        Args:
            request: HTTPRequest to validate

        Returns:
            Tuple of (is_valid, list of issues)
        """
        issues = []

        # Check method
        valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        if request.method not in valid_methods:
            issues.append(f"Invalid HTTP method: {request.method}")

        # Check URL
        try:
            parsed = urlparse(request.url)
            if not parsed.scheme:
                issues.append("URL missing scheme (http/https)")
            if not parsed.netloc:
                issues.append("URL missing host")
        except Exception as e:
            issues.append(f"Invalid URL: {e}")

        # Check headers
        if request.method in ['POST', 'PUT', 'PATCH'] and request.body:
            if 'Content-Type' not in request.headers:
                issues.append("POST/PUT/PATCH request with body should have Content-Type header")

        # Check body for POST/PUT/PATCH
        if request.method in ['POST', 'PUT', 'PATCH']:
            if not request.body and not request.query_params:
                issues.append(f"{request.method} request has no body or query parameters")

        is_valid = len(issues) == 0
        return is_valid, issues

