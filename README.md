# BountyBot - AI-Powered Bug Bounty Validation Framework

## Overview

BountyBot is an enterprise-grade AI-powered security validation framework that automates vulnerability report triage and validation for bug bounty programs. It combines multi-pass AI analysis, static code analysis, dynamic security scanning, and automated remediation to provide instant, confident assessments of security reports.

### Core Capabilities

- AI-powered vulnerability validation with multi-pass analysis
- Static code analysis across 8+ programming languages
- Dynamic security scanning with 6 vulnerability types
- HTML/JSON/Markdown report parsing from major bug bounty platforms
- Automated code fix generation with efficient AI chunking
- WAF rule generation (ModSecurity, AWS WAF, Cloudflare)
- Compensating control recommendations
- CVSS v3.1 scoring and risk assessment
- Duplicate detection and false positive analysis
- REST API with authentication and rate limiting
- PostgreSQL/SQLite database backend
- Real-time webhooks with HMAC signatures
- Cost tracking and budget enforcement

### Key Features

**Validation Pipeline:**
- Quality assessment (completeness, clarity, technical depth)
- Plausibility analysis (technical feasibility, security impact)
- Code analysis (static analysis, vulnerability detection)
- Dynamic scanning (safe exploitation testing)
- Final verdict generation with confidence scoring

**Remediation Engine:**
- AI-generated code fixes with before/after diffs
- WAF rules for multiple platforms
- Compensating controls and defense strategies
- Detection rules and monitoring queries
- Testing and validation criteria

**Performance:**
- 10-60 second validation time per report
- Efficient AI chunking to minimize token costs
- Response caching with SHA-256 keys
- Rate limiting with token bucket algorithm
- Circuit breaker for API resilience

## Installation

### Requirements

- Python 3.8+
- Anthropic API key (Claude)
- Optional: PostgreSQL for production deployments

### Quick Install

```bash
# Clone repository
git clone https://github.com/clay-good/bountybot
cd bountybot

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -e .

# Configure API key
export ANTHROPIC_API_KEY="your-api-key-here"

# Verify installation
python3 test_installation.py
```

## Usage

### Command Line Interface

```bash
# Validate single report (JSON/Markdown/HTML)
python3 -m bountybot.cli report.json

# Validate HTML report from bug bounty platform
python3 -m bountybot.cli hackerone_report.html --codebase /path/to/src

# With codebase analysis for code fixes
python3 -m bountybot.cli report.json --codebase /path/to/src --output result.json

# Batch processing with parallel workers
python3 -m bountybot.cli reports/ --batch --batch-workers 5

# With dynamic scanning (safe exploitation testing)
python3 -m bountybot.cli report.json --target-url https://example.com/api
```

### Python API

```python
from bountybot import Orchestrator
from bountybot.config_loader import ConfigLoader

# Load configuration
config = ConfigLoader.load_config('config.yaml')

# Initialize orchestrator
orchestrator = Orchestrator(config)

# Validate report
result = orchestrator.validate_report(
    report_path='report.html',
    codebase_path='/path/to/src',
    target_url='https://example.com/api'
)

# Access results
print(f"Verdict: {result.verdict.value}")
print(f"Confidence: {result.confidence}%")
print(f"CVSS Score: {result.cvss_score.overall_score}")

# Access remediation plan
plan = result.remediation_plan
for fix in plan.code_fixes:
    print(f"File: {fix.file_path}")
    print(f"Fix: {fix.explanation}")
    print(f"Diff:\n{fix.diff}")

for rule in plan.waf_rules:
    print(f"WAF Platform: {rule.rule_type}")
    print(f"Rule:\n{rule.rule_content}")
```

### REST API Server

```bash
# Start API server
python3 -m bountybot.api.cli --host 0.0.0.0 --port 8000 --workers 4

# Or use CLI command
bountybot-api --workers 4
```

```bash
# Validate report via API
curl -X POST http://localhost:8000/api/v1/validate \
  -H "X-API-Key: your-api-key" \
  -F "report=@report.html" \
  -F "codebase_path=/path/to/src"

# Batch validation
curl -X POST http://localhost:8000/api/v1/batch \
  -H "X-API-Key: your-api-key" \
  -F "reports=@reports.zip"

# Get metrics
curl http://localhost:8000/api/v1/metrics \
  -H "X-API-Key: your-api-key"
```

API documentation available at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### Docker Deployment

```bash
# Build image
docker build -t bountybot:latest .

# Run validation
docker run -e ANTHROPIC_API_KEY="your-key" \
  -v $(pwd)/reports:/app/reports \
  bountybot:latest python3 -m bountybot.cli /app/reports/report.html

# Run API server
docker run -p 8000:8000 \
  -e ANTHROPIC_API_KEY="your-key" \
  bountybot:latest python3 -m bountybot.api.cli --host 0.0.0.0
```

## Configuration

### config.yaml

```yaml
api:
  default_provider: anthropic
  providers:
    anthropic:
      api_key: ${ANTHROPIC_API_KEY}
      model: claude-3-5-sonnet-20241022
      max_tokens: 4096
      temperature: 0.0
      cache_ttl: 3600
      rate_limit:
        requests_per_minute: 50
        tokens_per_minute: 100000

code_analysis:
  enabled: true
  languages: [python, javascript, java, php, ruby, go, csharp, typescript]
  max_file_size_mb: 10

dynamic_scanning:
  enabled: true
  timeout_seconds: 30
  max_requests: 10
  scan_types: [sqli, xss, cmdi, path_traversal, ssrf, open_redirect]

database:
  type: postgresql  # or sqlite
  host: localhost
  port: 5432
  database: bountybot
  username: bountybot
  password: ${DB_PASSWORD}

webhooks:
  enabled: true
  secret_key: ${WEBHOOK_SECRET}
  retry_attempts: 5
  timeout_seconds: 30

integrations:
  enabled: true
  jira:
    enabled: true
    url: https://company.atlassian.net
    api_token: ${JIRA_API_TOKEN}
    project_key: SEC
  slack:
    enabled: true
    webhook_url: ${SLACK_WEBHOOK_URL}
```

### Environment Variables

```bash
# Required
export ANTHROPIC_API_KEY="sk-ant-..."

# Optional
export DB_PASSWORD="secure-password"
export WEBHOOK_SECRET="random-secret-key"
export JIRA_API_TOKEN="jira-token"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
```

## Architecture

### Validation Pipeline

1. **Report Parsing** - Parse HTML/JSON/Markdown from bug bounty platforms
2. **Quality Assessment** - Evaluate report completeness and clarity
3. **Plausibility Analysis** - Assess technical feasibility
4. **Code Analysis** - Static analysis of codebase (optional)
5. **Dynamic Scanning** - Safe exploitation testing (optional)
6. **Verdict Generation** - Final assessment with confidence score
7. **CVSS Scoring** - Automated severity calculation
8. **Duplicate Detection** - Check against historical reports
9. **False Positive Analysis** - ML-based FP detection
10. **Remediation Planning** - Generate fixes and WAF rules
11. **Integration Execution** - Create tickets, send notifications

### Remediation Engine

**Code Fixer:**
- AI-powered code fix generation
- Efficient chunking for large files (3000 token chunks)
- Language-specific pattern detection
- Before/after diffs with explanations
- Confidence scoring

**WAF Rule Generator:**
- ModSecurity rule generation
- AWS WAF JSON configuration
- Cloudflare expression-based rules
- Attack pattern matching
- False positive risk assessment

**Compensating Controls:**
- Input validation recommendations
- Rate limiting strategies
- Network segmentation guidance
- Monitoring and detection rules
- Testing and validation criteria

### AI Chunking Strategy

To minimize API costs, BountyBot implements intelligent chunking:

1. **Token Estimation** - Estimate tokens before API calls (1 token ~= 4 chars)
2. **Smart Splitting** - Split at function/class boundaries, not arbitrary lines
3. **Context Preservation** - Include surrounding context for accurate analysis
4. **Threshold-Based** - Only chunk if content exceeds 3000 tokens
5. **Result Merging** - Combine chunk results into coherent output

Cost reduction: 40-60% compared to naive full-content submission

## Supported Vulnerability Types

SQL Injection, XSS, CSRF, SSRF, RCE, XXE, File Upload, Path Traversal, Command Injection, SSTI, Insecure Deserialization, IDOR, Authentication Bypass, Business Logic Flaws, GraphQL Injection, NoSQL Injection, JWT Vulnerabilities, CORS Misconfiguration, Open Redirect

## Example Workflow

### Scenario: Security Engineer at Google

A security engineer downloads an HTML report from HackerOne and validates it:

```bash
# Download HTML report from HackerOne
# report.html contains vulnerability details

# Validate with BountyBot
python3 -m bountybot.cli report.html \
  --codebase /path/to/google/codebase \
  --output-dir ./results

# Results include:
# - Validation verdict with confidence score
# - CVSS score and severity
# - Code fixes with diffs
# - WAF rules (ModSecurity, AWS WAF, Cloudflare)
# - Compensating controls
# - Detection rules
# - Testing steps
```

### Output Structure

```
results/
├── validation_result.json       # Complete validation data
├── validation_result.md         # Human-readable report
├── validation_result.html       # Interactive HTML report
└── remediation_plan.json        # Detailed remediation guidance
```

### Remediation Plan Contents

**Code Fixes:**
```python
# File: app/api/user.py
# Line: 45
# Vulnerability: SQL Injection

# Before (Vulnerable):
query = f"SELECT * FROM users WHERE id = {user_id}"

# After (Fixed):
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))

# Explanation: Use parameterized queries to prevent SQL injection
```

**WAF Rules:**
```apache
# ModSecurity Rule
SecRule REQUEST_URI|ARGS|REQUEST_BODY "@rx (?i)(union.*select|select.*from)" \
    "id:900001,phase:2,block,log,msg:'SQL Injection Detected'"
```

**Compensating Controls:**
- Deploy WAF rules immediately
- Enable query logging for affected endpoints
- Implement rate limiting (10 req/min per IP)
- Add input validation allowlist
- Monitor for SQL error patterns

## Testing

```bash
# Run all tests
python3 -m pytest tests/ -v

# Run specific test suite
python3 -m pytest tests/test_orchestrator.py -v

# Run with coverage
python3 -m pytest tests/ --cov=bountybot --cov-report=html

# Test installation
python3 test_installation.py
```

Test Coverage: 451 tests, 100% passing

## Performance Benchmarks

| Operation | Time | Cost |
|-----------|------|------|
| Parse HTML report | 0.1s | $0.00 |
| AI quality assessment | 2-3s | $0.02 |
| AI plausibility analysis | 2-3s | $0.02 |
| Code analysis | 1-5s | $0.00 |
| Dynamic scanning | 5-15s | $0.00 |
| AI verdict generation | 3-5s | $0.03 |
| Remediation plan | 5-10s | $0.05 |
| **Total** | **10-60s** | **$0.12** |

Cost optimization through chunking: 40-60% reduction

## Database Schema

BountyBot supports PostgreSQL and SQLite for persistence:

```sql
-- Reports table
CREATE TABLE reports (
    id SERIAL PRIMARY KEY,
    title VARCHAR(500),
    vulnerability_type VARCHAR(100),
    severity VARCHAR(20),
    submitted_by VARCHAR(200),
    submitted_at TIMESTAMP,
    raw_report TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Validation results table
CREATE TABLE validation_results (
    id SERIAL PRIMARY KEY,
    report_id INTEGER REFERENCES reports(id),
    verdict VARCHAR(20),
    confidence INTEGER,
    cvss_score FLOAT,
    processing_time FLOAT,
    total_cost FLOAT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Webhooks table
CREATE TABLE webhooks (
    id SERIAL PRIMARY KEY,
    url VARCHAR(500),
    secret_key VARCHAR(100),
    events TEXT[],
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW()
);
```

## API Reference

### REST Endpoints

**POST /api/v1/validate**
- Validate single report
- Request: multipart/form-data with report file
- Response: ValidationResult JSON

**POST /api/v1/batch**
- Batch validation
- Request: multipart/form-data with multiple reports
- Response: Array of ValidationResult JSON

**GET /api/v1/health**
- Health check
- Response: {status: "healthy", version: "2.19.0"}

**GET /api/v1/metrics**
- System metrics
- Response: Validation stats, costs, performance

**POST /api/v1/webhooks**
- Create webhook
- Request: {url, secret, events[]}
- Response: Webhook object

**GET /api/v1/webhooks**
- List webhooks
- Response: Array of webhook objects

**DELETE /api/v1/webhooks/{id}**
- Delete webhook
- Response: {success: true}

### Authentication

All API requests require X-API-Key header:

```bash
curl -H "X-API-Key: your-api-key" http://localhost:8000/api/v1/validate
```

Configure API keys in config.yaml:

```yaml
api_server:
  api_keys:
    - key: "your-api-key"
      name: "production"
      rate_limit: 100
```

## Integrations

### Jira

Automatically create tickets for validated vulnerabilities:

```yaml
integrations:
  jira:
    enabled: true
    url: https://company.atlassian.net
    api_token: ${JIRA_API_TOKEN}
    project_key: SEC
    issue_type: Bug
    priority_mapping:
      critical: Highest
      high: High
      medium: Medium
      low: Low
```

### Slack

Send notifications to Slack channels:

```yaml
integrations:
  slack:
    enabled: true
    webhook_url: ${SLACK_WEBHOOK_URL}
    channel: "#security-alerts"
    notify_on: [VALID, LIKELY_VALID]
```

### PagerDuty

Escalate critical vulnerabilities:

```yaml
integrations:
  pagerduty:
    enabled: true
    api_key: ${PAGERDUTY_API_KEY}
    service_id: ${PAGERDUTY_SERVICE_ID}
    escalate_on: [VALID]
    severity_threshold: critical
```

## Security Considerations

**API Security:**
- API key authentication with SHA-256 hashing
- Rate limiting per key
- Request size limits
- CORS configuration
- HTTPS enforcement in production

**Data Security:**
- Sensitive data encryption at rest
- Secure credential storage
- Audit logging for all operations
- PII redaction in logs

**Scanning Safety:**
- Non-destructive payloads only
- Rate limiting to prevent DoS
- Explicit permission required
- Configurable scan limits
- SSL verification enabled by default

## Troubleshooting

**Issue: API rate limit exceeded**
```bash
# Solution: Increase rate limit in config
api:
  providers:
    anthropic:
      rate_limit:
        requests_per_minute: 100  # Increase this
```

**Issue: Out of memory during batch processing**
```bash
# Solution: Reduce batch workers
python3 -m bountybot.cli reports/ --batch --batch-workers 2
```

**Issue: Dynamic scanning timeout**
```bash
# Solution: Increase timeout in config
dynamic_scanning:
  timeout_seconds: 60  # Increase from 30
```

**Issue: Database connection failed**
```bash
# Solution: Check database credentials and connectivity
export DATABASE_URL="postgresql://user:pass@localhost:5432/bountybot"
python3 -m bountybot.database.cli init  # Reinitialize
```

## Development

### Running Tests

```bash
# All tests
python3 -m pytest tests/ -v

# Specific module
python3 -m pytest tests/test_remediation.py -v

# With coverage
python3 -m pytest tests/ --cov=bountybot --cov-report=html
```

### Code Quality

```bash
# Format code
black bountybot/ tests/

# Lint
flake8 bountybot/ tests/

# Type checking
mypy bountybot/
```

## Project Structure

```
bountybot/
├── ai_providers/          # AI provider implementations
├── analysis/              # Advanced analysis modules
├── api/                   # REST API server
├── database/              # Database models and migrations
├── integrations/          # External service integrations
├── ml/                    # Machine learning modules
├── parsers/               # Report parsers (JSON, Markdown, HTML)
├── remediation/           # Code fixes and WAF rules
├── scanners/              # Dynamic security scanners
├── scoring/               # CVSS and risk scoring
├── validators/            # Validation logic
├── cli.py                 # Command-line interface
├── orchestrator.py        # Main workflow coordinator
└── models.py              # Data models

tests/                     # 451 passing tests
config/                    # Configuration files
examples/                  # Example reports
docs/                      # Additional documentation
```

## Version History

**v2.19.0** - Current
- Added HTML report parsing
- Implemented remediation engine with code fixes
- Added WAF rule generation (ModSecurity, AWS WAF, Cloudflare)
- Implemented AI chunking for cost optimization
- Added compensating controls recommendations

**v2.18.0**
- Added machine learning module
- Implemented pattern learning and anomaly detection
- Added researcher profiling

**v2.17.0**
- Added dynamic security scanning
- Implemented 6 vulnerability scan types
- Added safe exploitation testing

**v2.16.0**
- Added REST API server
- Implemented webhooks system
- Added database backend
