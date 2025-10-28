# 🎮 BountyBot Demos Guide

This guide provides instructions for running BountyBot demos to explore its features and capabilities.

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start Demos](#quick-start-demos)
3. [Core Feature Demos](#core-feature-demos)
4. [Advanced Feature Demos](#advanced-feature-demos)
5. [Integration Demos](#integration-demos)
6. [Demo Scenarios](#demo-scenarios)

---

## Prerequisites

### Installation

```bash
# Install BountyBot
pip install -e .

# Install demo dependencies
pip install -r requirements.txt
```

### Environment Setup

Create a `.env` file:

```bash
# AI Provider Keys
ANTHROPIC_API_KEY=your-anthropic-key
OPENAI_API_KEY=your-openai-key

# Demo Configuration
DEMO_MODE=true
CODEBASE_PATH=./examples/vulnerable_app
```

---

## 🚀 Quick Start Demos

### 1. Basic Validation Demo

**Purpose**: Validate a simple SQL injection report

```bash
python demos/demo_api.py
```

**What it demonstrates**:
- Report parsing and validation
- Code analysis
- AI-powered assessment
- Payout calculation

**Expected output**:
```
✅ Validation Result:
   - Approved: True
   - Confidence: 0.85
   - Severity: High
   - Payout: $500
   - Reason: SQL injection confirmed in /api/users endpoint
```

---

### 2. Advanced Features Demo

**Purpose**: Showcase all validation features

```bash
python demos/demo_advanced_features.py
```

**What it demonstrates**:
- PoC execution
- Context-aware code analysis
- Security control verification
- Environment validation
- Duplicate detection

**Expected output**:
```
🔍 Running comprehensive validation...

1. PoC Execution: ✅ Exploit successful
2. Code Analysis: ✅ Vulnerable code found (line 42)
3. Security Controls: ⚠️ WAF not blocking attack
4. Environment Check: ✅ Applies to production
5. Duplicate Check: ✅ No duplicates found

Final Decision: APPROVED
Confidence: 0.92
Payout: $750
```

---

## 🎯 Core Feature Demos

### 3. PoC Execution Demo

**Purpose**: Demonstrate safe PoC execution

```bash
python demos/demo_poc_executor.py
```

**What it demonstrates**:
- HTTP request replay
- Response analysis
- Vulnerability indicator detection
- Safety checks

**Example scenarios**:
- SQL injection PoC
- XSS PoC
- Command injection PoC
- Path traversal PoC

---

### 4. Code Analysis Demo

**Purpose**: Show AST-based code analysis

```bash
python demos/demo_advanced_analysis.py
```

**What it demonstrates**:
- Taint tracking
- Data flow analysis
- Framework detection
- Sanitization detection

**Example output**:
```
📊 Code Analysis Results:

Taint Sources Found: 3
  - request.GET['id'] (line 15)
  - request.POST['username'] (line 23)
  - request.args.get('query') (line 31)

Data Flow Paths: 2
  Path 1: request.GET['id'] → user_id → execute() [VULNERABLE]
  Path 2: request.POST['username'] → sanitize() → query [SAFE]

Framework: Django
Protections: CSRF, ORM, Autoescape
Confidence: 0.88
```

---

### 5. Security Control Verification Demo

**Purpose**: Test WAF/IPS effectiveness

```bash
python demos/demo_security_controls.py
```

**What it demonstrates**:
- WAF rule testing
- Input validation checking
- Endpoint protection analysis
- Control recommendations

**Example output**:
```
🛡️ Security Control Test Results:

Test 1: SQL Injection Payload
  Payload: ' OR '1'='1
  Status: ❌ NOT BLOCKED
  Response: 200 OK
  
Test 2: XSS Payload
  Payload: <script>alert('XSS')</script>
  Status: ✅ BLOCKED
  Response: 403 Forbidden

Overall Effectiveness: PARTIALLY EFFECTIVE
Recommendation: Update WAF rules for SQL injection
```

---

### 6. Environment Validation Demo

**Purpose**: Check environment-specific applicability

```bash
python demos/demo_environment.py
```

**What it demonstrates**:
- Network accessibility checks
- Feature flag verification
- Access control analysis
- Deployment configuration

**Example output**:
```
🌍 Environment Validation Results:

Environment: Production
  ✅ Endpoint is publicly accessible
  ✅ Feature 'user-api' is enabled
  ✅ Service 'api-server' is deployed
  ⚠️ Authentication required but vulnerability doesn't need it
  
Applicability: PARTIALLY APPLICABLE
Confidence: 0.75
Affected Environments: Production, Staging
```

---

## 🔬 Advanced Feature Demos

### 7. ML-Powered Analysis Demo

**Purpose**: Demonstrate machine learning features

```bash
python demos/demo_ml.py
```

**What it demonstrates**:
- Vulnerability classification
- Severity prediction
- Pattern recognition
- Model training

---

### 8. Continuous Validation Demo

**Purpose**: Show regression testing capabilities

```bash
python demos/demo_continuous_validation.py
```

**What it demonstrates**:
- Automated regression tests
- PoC replay
- Vulnerability lifecycle tracking
- Security posture monitoring

---

### 9. Collaboration Demo

**Purpose**: Demonstrate team collaboration features

```bash
python demos/demo_collaboration.py
```

**What it demonstrates**:
- Comment system
- Activity feed
- SLA management
- Workflow automation

---

## 🔌 Integration Demos

### 10. API Integration Demo

**Purpose**: Show REST API usage

```bash
# Start API server
python -m bountybot.api.server

# In another terminal, run demo
python demos/demo_api_integration.py
```

**What it demonstrates**:
- REST API endpoints
- Authentication
- Webhook integration
- Real-time updates

---

### 11. CI/CD Integration Demo

**Purpose**: Demonstrate CI/CD pipeline integration

```bash
python demos/demo_cicd.py
```

**What it demonstrates**:
- GitHub Actions integration
- GitLab CI integration
- Automated validation in pipelines
- Report generation

---

## 📖 Demo Scenarios

### Scenario 1: SQL Injection Report

**File**: `examples/sql_injection_report.json`

```bash
python -c "
from bountybot import Orchestrator
import json

with open('examples/sql_injection_report.json') as f:
    report = json.load(f)

orchestrator = Orchestrator()
result = orchestrator.validate_report(report)
print(json.dumps(result, indent=2))
"
```

---

### Scenario 2: XSS Report

**File**: `examples/xss_report.md`

```bash
python -c "
from bountybot import Orchestrator

with open('examples/xss_report.md') as f:
    report_text = f.read()

orchestrator = Orchestrator()
result = orchestrator.validate_report_from_text(report_text)
print(f'Approved: {result[\"approved\"]}')
print(f'Confidence: {result[\"confidence\"]}')
print(f'Payout: ${result[\"payout_amount\"]}')
"
```

---

### Scenario 3: False Positive Detection

**Purpose**: Show how BountyBot detects false positives

```bash
python demos/demo_false_positive.py
```

**Example**:
```
📋 Report: "SQL Injection in /api/users"

🔍 Validation Steps:
1. PoC Execution: ❌ Failed (no SQL error)
2. Code Analysis: ❌ No vulnerable code found
3. Security Controls: ✅ WAF blocking attack
4. AI Assessment: Low confidence (0.25)

Final Decision: REJECTED (False Positive)
Reason: No evidence of exploitable vulnerability
```

---

### Scenario 4: Duplicate Detection

**Purpose**: Demonstrate duplicate prevention

```bash
python demos/demo_duplicate.py
```

**Example**:
```
📋 Report 1: "SQL Injection in /api/users"
   Status: ✅ APPROVED
   Payout: $500

📋 Report 2: "SQL Injection in /api/users endpoint"
   Status: ❌ REJECTED (Duplicate)
   Similarity: 0.95
   Original: Report #1234
   Payout: $0
```

---

## 🎓 Learning Path

### Beginner
1. Start with `demo_api.py` - Basic validation
2. Try `demo_advanced_features.py` - See all features
3. Explore `examples/` - Sample reports

### Intermediate
4. Run `demo_advanced_analysis.py` - Code analysis
5. Try `demo_ml.py` - ML features
6. Experiment with `demo_continuous_validation.py`

### Advanced
7. Set up `demo_api_integration.py` - API usage
8. Configure `demo_cicd.py` - Pipeline integration
9. Customize validation logic for your needs

---

## 🐛 Troubleshooting

### Demo fails with "API key not found"
```bash
# Set your API key
export ANTHROPIC_API_KEY=your-key
```

### Demo fails with "Codebase not found"
```bash
# Set codebase path
export CODEBASE_PATH=./examples/vulnerable_app
```

### Demo runs but no output
```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
python demos/demo_api.py
```

---

## 📊 Demo Metrics

After running demos, view metrics:

```bash
# View validation statistics
python -c "
from bountybot.analytics import AnalyticsEngine
analytics = AnalyticsEngine()
stats = analytics.get_validation_stats()
print(f'Total Validations: {stats[\"total\"]}')
print(f'Approved: {stats[\"approved\"]}')
print(f'Rejected: {stats[\"rejected\"]}')
print(f'Average Confidence: {stats[\"avg_confidence\"]:.2f}')
"
```

---

## 🎯 Next Steps

After exploring demos:

1. **Read Documentation**: Check `docs/` for detailed guides
2. **Run Tests**: Execute `pytest tests/` to see test coverage
3. **Customize Configuration**: Modify `config.yaml` for your needs
4. **Deploy**: Follow deployment guide in `docs/DEPLOYMENT.md`
5. **Integrate**: Connect with your bug bounty platform

---

## 💡 Tips

- **Start Simple**: Begin with basic demos before advanced ones
- **Read Output**: Demos provide detailed explanations
- **Experiment**: Modify demo code to test different scenarios
- **Check Logs**: Enable DEBUG logging for troubleshooting
- **Use Examples**: Sample reports in `examples/` are great starting points

---

**Happy Demoing! 🚀**

