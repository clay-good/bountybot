# bountybot - Enterprise Bug Bounty Validation Framework

**What:** AI-powered automated validation framework for web and API security vulnerability reports

**Who:** Security teams at bug bounty platforms, FAANG companies, financial institutions, and enterprises

**Why:** Reduce manual triage time by 70-80%, validate vulnerabilities in seconds, save $4,500-$13,500/month

**How:** AI analysis + static code analysis + automated testing = instant, confident vulnerability validation

---

## Quick Start

### Installation (2 minutes)

```bash
# Clone repository
git clone https://github.com/clay-good/bountybot
cd bountybot

# Install dependencies
pip install -e .

# Configure API key
export ANTHROPIC_API_KEY="your-api-key-here"

# Validate a report
python3 -m bountybot.cli report.json
```

### Usage Without Codebase

**Use Case:** Validate vulnerability reports based on description, PoC, and HTTP requests only

```bash
# Single report validation
python3 -m bountybot.cli report.json

# Batch validation
python3 -m bountybot.cli reports/ --batch

# Multiple output formats
python3 -m bountybot.cli report.json --output json,markdown,html
```

**What happens:** bountybot analyzes the report content, extracts HTTP requests, validates the vulnerability logic, and provides a verdict with confidence score.

### Usage With Codebase

**Use Case:** Validate vulnerability reports AND verify against actual application source code

```bash
# Validate with codebase analysis
python3 -m bountybot.cli report.json --codebase /path/to/application/src

# Validate SQL injection with codebase
python3 -m bountybot.cli sqli_report.json --codebase ./webapp/src

# Batch validation with codebase
python3 -m bountybot.cli reports/ --batch --codebase ./src
```

**What happens:** bountybot performs static code analysis on your codebase, searches for the vulnerable code patterns mentioned in the report, validates if the vulnerability actually exists in your code, and provides detailed findings with code locations.

**Supported Languages:** Python, JavaScript, TypeScript, Java, PHP, Ruby, Go, C#

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Output Formats](#output-formats)
- [Vulnerability Coverage](#vulnerability-coverage)
- [Integration](#integration)
- [Security](#security)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

### What is bountybot?

bountybot is an enterprise-grade security validation framework that automates the triage and validation of vulnerability reports from bug bounty programs. It combines AI-powered analysis with static code analysis to provide instant, confident assessments of security reports.

### Problem Statement

Modern security teams face critical challenges:

- **Volume:** Organizations receive 100-500+ vulnerability submissions monthly
- **False Positives:** Only 5-10% represent genuine, exploitable vulnerabilities
- **Time:** Manual triage requires 30-60 minutes per report
- **Cost:** Security engineers spend $50-150 per report on initial assessment
- **Backlog:** Triage delays lead to SLA violations and missed critical vulnerabilities

### Solution

bountybot provides:

- **Instant Analysis:** Validate reports in 10-60 seconds
- **High Accuracy:** 70-80% reduction in manual triage time
- **Confidence Scoring:** Clear verdicts with confidence levels
- **Code Verification:** Static analysis to confirm vulnerabilities in source code
- **Batch Processing:** Handle hundreds of reports automatically
- **Professional Output:** JSON, Markdown, HTML reports with BLUF style

### Value Proposition

For a security team processing 100 reports per month:

| Metric | Before bountybot | With bountybot | Savings |
|--------|------------------|----------------|---------|
| Time per report | 45 minutes | 10 minutes | 35 minutes |
| Monthly time | 75 hours | 17 hours | 58 hours |
| Monthly cost | $7,500 | $1,700 | $5,800 |
| Response time | 24-48 hours | < 1 hour | Instant |

---

## Features

### Core Capabilities

- **AI-Powered Analysis:** Multi-pass validation using Claude Sonnet 4
- **Static Code Analysis:** Automated code review across 8+ languages
- **HTTP Request Extraction:** Automatic parsing of cURL, raw HTTP, and code snippets
- **PoC Generation:** Automated proof-of-concept creation for validated vulnerabilities
- **Batch Processing:** Parallel processing of multiple reports
- **Confidence Scoring:** 0-100% confidence levels for all verdicts
- **Cost Tracking:** Real-time API cost monitoring and budgeting

### Validation Process

1. **Report Parsing:** Extract vulnerability details, PoC, HTTP requests
2. **Quality Assessment:** Evaluate report completeness and clarity
3. **Plausibility Analysis:** Check if vulnerability is theoretically possible
4. **Code Analysis:** Search codebase for vulnerable patterns (if provided)
5. **Final Verdict:** VALID, INVALID, or UNCERTAIN with confidence score
6. **PoC Generation:** Create working exploits for valid vulnerabilities

### Output Formats

All outputs use **BLUF (Bottom Line Up Front)** communication style:

- **JSON:** Structured data with verdict at top, suitable for automation
- **Markdown:** Professional reports with clear verdict, findings, and recommendations
- **HTML:** Interactive reports with syntax highlighting and navigation
- **PoC:** Executable proof-of-concept in multiple formats (cURL, Python, JavaScript)

---

## Installation

### System Requirements

- **Python:** 3.8 or higher (3.10+ recommended)
- **Memory:** 2GB minimum, 4GB recommended
- **Disk:** 10GB for installation and logs
- **API Key:** Anthropic API key (Claude Sonnet 4)

### Quick Installation

```bash
# Clone repository
git clone https://github.com/clay-good/bountybot
cd bountybot

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e .

# Verify installation
python3 test_installation.py
```

### Configuration

Create `.env` file in project root:

```bash
# Required: Anthropic API key
ANTHROPIC_API_KEY=your-api-key-here

# Optional: Cost management
BOUNTYBOT_MAX_COST_PER_RUN=10.0
BOUNTYBOT_DAILY_BUDGET=500.0

# Optional: Performance
BOUNTYBOT_PARALLEL_TASKS=4
BOUNTYBOT_BATCH_WORKERS=3
```

### Docker Installation

```bash
# Build image
docker build -t bountybot:latest .

# Run container
docker run -e ANTHROPIC_API_KEY="your-key" \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/validation_results:/app/validation_results \
  bountybot:latest report.json
```

---

## Usage

### Basic Usage

#### Validate Single Report

```bash
# Simplest usage
python3 -m bountybot.cli report.json

# With specific output format
python3 -m bountybot.cli report.json --output markdown

# With multiple formats
python3 -m bountybot.cli report.json --output json,markdown,html

# With custom output directory
python3 -m bountybot.cli report.json --output-dir ./results
```

#### Validate With Codebase

```bash
# Point to your application source code
python3 -m bountybot.cli report.json --codebase /path/to/app/src

# Example: Validate SQL injection with codebase
python3 -m bountybot.cli sqli_report.json --codebase ./webapp/src

# Example: Validate XSS with codebase
python3 -m bountybot.cli xss_report.json --codebase ./frontend/src
```

**What --codebase does:**
1. Scans your source code for vulnerable patterns
2. Searches for the specific code mentioned in the report
3. Validates if the vulnerability actually exists
4. Provides file paths and line numbers of vulnerable code
5. Increases confidence in validation verdict

#### Batch Processing

```bash
# Validate all reports in directory
python3 -m bountybot.cli reports/ --batch

# Batch with codebase analysis
python3 -m bountybot.cli reports/ --batch --codebase ./src

# Batch with parallel workers
python3 -m bountybot.cli reports/ --batch --batch-workers 5

# Batch with cost limit
python3 -m bountybot.cli reports/ --batch --max-cost 50.0
```

### Advanced Usage

#### Custom AI Provider

```bash
# Use specific AI model
python3 -m bountybot.cli report.json --model claude-sonnet-4-20250514

# Use different provider (if configured)
python3 -m bountybot.cli report.json --provider openai
```

#### Dynamic Testing (Use with Caution)

```bash
# Enable safe dynamic testing
python3 -m bountybot.cli report.json --target https://test.example.com

# Note: Only use on systems you own or have permission to test
```

### Report Format

bountybot accepts reports in JSON or Markdown format:

#### JSON Format

```json
{
  "title": "SQL Injection in User Search",
  "vulnerability_type": "SQL Injection",
  "severity": "HIGH",
  "affected_components": ["User search API", "/api/users/search"],
  "reproduction_steps": [
    "Navigate to /api/users/search",
    "Enter payload: ' OR '1'='1",
    "Observe database error revealing SQL injection"
  ],
  "proof_of_concept": "curl -X POST https://example.com/api/users/search -d \"query=' OR '1'='1\"",
  "impact_description": "Attacker can extract entire database contents"
}
```

#### Markdown Format

```markdown
# SQL Injection in User Search

## Vulnerability Type
SQL Injection

## Severity
HIGH

## Affected Components
- User search API
- /api/users/search

## Reproduction Steps
1. Navigate to /api/users/search
2. Enter payload: ' OR '1'='1
3. Observe database error

## Proof of Concept
\```bash
curl -X POST https://example.com/api/users/search -d "query=' OR '1'='1"
\```

## Impact
Attacker can extract entire database contents
```

---

## Configuration

### Configuration File

Create `config/production.yaml`:

```yaml
api:
  default_provider: anthropic
  providers:
    anthropic:
      api_key: ${ANTHROPIC_API_KEY}
      model: claude-sonnet-4-20250514
      max_tokens: 8192
      temperature: 0.3

validation:
  parallel_tasks: 4
  confidence_threshold: 60

code_analysis:
  enabled: true
  languages:
    - python
    - javascript
    - java
    - php
    - ruby
    - go
    - typescript
    - csharp
  max_file_size_mb: 10

output:
  formats:
    - json
    - markdown
    - html
  directory: ./validation_results

cost_management:
  max_cost_per_validation: 10.00
  max_daily_cost: 500.00
  track_usage: true

logging:
  level: INFO
  file: ./bountybot.log
```

### Environment Variables

```bash
# Required
ANTHROPIC_API_KEY=your-api-key-here

# Optional
BOUNTYBOT_LOG_LEVEL=INFO
BOUNTYBOT_MAX_COST_PER_RUN=10.0
BOUNTYBOT_DAILY_BUDGET=500.0
BOUNTYBOT_PARALLEL_TASKS=4
BOUNTYBOT_BATCH_WORKERS=3
BOUNTYBOT_OUTPUT_DIR=./validation_results
```

---

## Output Formats

### BLUF Style

All outputs use **Bottom Line Up Front (BLUF)** communication style:

1. **Verdict First:** VALID, INVALID, or UNCERTAIN at the very top
2. **Action Required:** Clear statement of what needs to be done
3. **Confidence Level:** Percentage confidence in the verdict
4. **One-Line Summary:** Executive summary of the finding
5. **Detailed Analysis:** Complete findings below

### JSON Output

```json
{
  "bluf": {
    "verdict": "VALID",
    "verdict_text": "VALID VULNERABILITY - IMMEDIATE ACTION REQUIRED",
    "action_required": "Immediate remediation required",
    "confidence_level": 85,
    "summary": "This is a VALID SQL Injection vulnerability that poses a HIGH risk...",
    "severity": "HIGH",
    "vulnerability_type": "SQL Injection"
  },
  "metadata": {
    "report_version": "2.0.0",
    "validation_timestamp": "2025-01-15T10:30:00Z",
    "processing_time_seconds": 15.3
  },
  "cvss_assessment": {
    "score": 8.5,
    "severity": "High",
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
  },
  "detailed_analysis": {
    ...
  }
}
```

### Markdown Output

```markdown
# VULNERABILITY VALIDATION REPORT

## BOTTOM LINE UP FRONT (BLUF)

### ✓ VALID VULNERABILITY
**Action Required:** IMMEDIATE ACTION REQUIRED

**Confidence Level:** 85%
**Severity:** HIGH
**Estimated CVSS 3.1 Score:** 8.5 (High)

**Summary:** This is a VALID SQL Injection vulnerability that poses a HIGH risk to the application. Immediate remediation is recommended.

---

## EXECUTIVE SUMMARY
...
```

---



## Vulnerability Coverage

bountybot includes comprehensive knowledge base for 19+ vulnerability types:

### Web Application Vulnerabilities

1. **SQL Injection (SQLi)** - Database query manipulation
2. **Cross-Site Scripting (XSS)** - Reflected, Stored, DOM-based
3. **Cross-Site Request Forgery (CSRF)** - Unauthorized actions
4. **Server-Side Request Forgery (SSRF)** - Internal network access
5. **Remote Code Execution (RCE)** - Arbitrary code execution
6. **XML External Entity (XXE)** - XML parser exploitation
7. **File Upload** - Unrestricted file upload vulnerabilities
8. **Path Traversal** - Directory traversal attacks
9. **Command Injection** - OS command execution
10. **Server-Side Template Injection (SSTI)** - Template engine exploitation
11. **Insecure Deserialization** - Object injection attacks
12. **Insecure Direct Object Reference (IDOR)** - Broken access control

### API Security Vulnerabilities

13. **API Authentication Bypass** - JWT, OAuth, API key issues
14. **Business Logic Flaws** - Workflow and validation bypasses
15. **GraphQL Injection** - GraphQL-specific attacks
16. **NoSQL Injection** - MongoDB, CouchDB, Redis exploitation
17. **JWT Vulnerabilities** - Token manipulation and bypass
18. **CORS Misconfiguration** - Cross-origin resource sharing issues
19. **Authentication Bypass** - Session and authentication flaws

Each vulnerability definition includes:
- 200+ lines of detailed information
- Common attack patterns and payloads
- Detection methods and testing procedures
- Mitigation strategies and secure code examples
- Compliance mappings (OWASP, CWE, NIST, PCI DSS)
- Real-world exploitation scenarios
