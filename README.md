# BountyBot - AI-Powered Bug Bounty Validation

**Automated validation platform for bug bounty programs**

BountyBot validates reported security vulnerabilities before payout, ensuring organizations only pay for real, exploitable threats in their actual codebase.

[![Tests](https://img.shields.io/badge/tests-1059%20passing-brightgreen)](./tests)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

## Overview

Bug bounty programs face a 30-40% false positive rate, costing organizations thousands in invalid payouts. BountyBot automates validation using:

- **PoC Execution** - Safely executes exploits to verify exploitability
- **AST-Based Code Analysis** - Taint tracking to find vulnerable code paths
- **Security Control Testing** - Verifies WAF/IPS effectiveness
- **Environment Validation** - Checks deployment-specific applicability
- **Duplicate Detection** - Prevents double-payment
- **AI Assessment** - Multi-pass validation with confidence scoring

**Results:** 70-85% reduction in false positives, 5-10x faster validation.

## Quick Start

### Installation

```bash
git clone https://github.com/clay-good/bountybot.git
cd bountybot
pip install -r requirements.txt
pip install -e .
```

### Configuration

Create `.env`:
```bash
ANTHROPIC_API_KEY=your_key_here
CODEBASE_PATH=/path/to/your/code
```

### Basic Usage

```python
from bountybot import Orchestrator
from bountybot.config_loader import ConfigLoader

config = ConfigLoader.load_config('config.yaml')
orchestrator = Orchestrator(config)

result = orchestrator.validate_report({
    'title': 'SQL Injection in /api/users',
    'description': 'User input not sanitized, allowing SQL injection',
    'severity': 'high',
    'vulnerability_type': 'sql_injection',
    'affected_endpoint': '/api/users',
    'poc': "curl -X POST http://example.com/api/users -d \"id=' OR '1'='1\""
})

print(f"Verdict: {result.verdict}")
print(f"Confidence: {result.confidence}")
print(f"Payout: ${result.payout_amount}")
```

## Architecture

### Validation Pipeline

```
Report → Parse → Pre-validate → Code Analysis → AI Validation →
PoC Execution → Security Controls → Environment Check →
Duplicate Detection → Payout Decision
```

### Core Components

- **Orchestrator** - Coordinates validation workflow
- **Validators** - AI, Code, PoC, Security Controls, Environment
- **Analysis Engines** - False positive detection, duplicate detection, complexity analysis
- **Payout Engine** - Calculates bounties based on severity, confidence, and complexity
- **Integration Manager** - Connects to HackerOne, Bugcrowd, GitHub, Jira, Slack

See [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) for detailed architecture.

## Features

### PoC Execution
- Safe execution with dangerous pattern blocking
- HTTP request replay and response analysis
- Timeout enforcement and rate limiting
- Evidence collection

### Code Analysis
- AST-based taint tracking
- Data flow analysis from sources to sinks
- Framework detection (Django, Flask, Express)
- Sanitization detection

### Security Control Testing
- WAF/IPS effectiveness verification
- Payload blocking detection
- Input validation testing
- Control recommendations

### Environment Validation
- Network accessibility checks
- Feature flag verification
- Access control analysis
- Service deployment validation

### Duplicate Detection
- Fuzzy text similarity
- HTTP request fingerprinting
- Payload similarity analysis
- Component matching

## Configuration

Create `config.yaml`:

```yaml
api:
  default_provider: anthropic
  providers:
    anthropic:
      api_key: ${ANTHROPIC_API_KEY}
      model: claude-3-5-sonnet-20241022

code_analysis:
  enabled: true
  codebase_path: /path/to/code
  context_aware: true

poc_execution:
  enabled: true
  timeout: 30
  allow_destructive: false

payout:
  confidence_threshold: 0.7
  require_code_analysis: true
  enable_duplicate_detection: true
```

## API Usage

Start the API server:
```bash
python -m bountybot.api.server
```

Validate a report:
```bash
curl -X POST http://localhost:8000/validate \
  -H "Authorization: Bearer your_token" \
  -H "Content-Type: application/json" \
  -d @report.json
```

See [docs/API.md](./docs/API.md) for complete API reference.

## Testing

```bash
pytest tests/ -v                    # Run all tests
pytest tests/ --cov=bountybot       # With coverage
pytest tests/test_validators.py     # Specific suite
```

**Status:** 1059/1059 tests passing

## Deployment

### Docker
```bash
docker build -t bountybot .
docker run -d -p 8000:8000 \
  -e ANTHROPIC_API_KEY=your_key \
  bountybot
```

### Kubernetes
```bash
kubectl apply -f k8s/deployment.yaml
```

### Helm
```bash
helm install bountybot ./helm/bountybot
```

See [docs/CICD.md](./docs/CICD.md) for CI/CD integration.

## Documentation

- [Architecture](./docs/ARCHITECTURE.md) - System design and components
- [API Reference](./docs/API.md) - REST API documentation
- [CI/CD Integration](./docs/CICD.md) - Pipeline setup
- [Backup & Recovery](./docs/BACKUP.md) - Data management

## Examples

See `examples/` directory for sample vulnerability reports:
- `sql_injection_report.json` - SQL injection example
- `xss_report.md` - XSS example
- `advanced_sqli_report.json` - Complex SQL injection

Run demos:
```bash
python demos/demo_api.py              # Basic validation
python demos/demo_advanced_features.py # All features
python demos/demo_ml.py               # ML analysis
```
