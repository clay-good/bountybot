"""
Demo: HTML Report Validation with Remediation
Demonstrates parsing HTML reports and generating comprehensive remediation plans.
"""

import sys
from pathlib import Path

# Add bountybot to path
sys.path.insert(0, str(Path(__file__).parent))

from bountybot.config_loader import ConfigLoader
from bountybot.orchestrator import Orchestrator


def create_sample_html_report():
    """Create a sample HTML report for testing."""
    html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>SQL Injection in User Search API - HackerOne Report</title>
</head>
<body>
    <div class="report-container">
        <h1 class="report-title">SQL Injection in User Search API</h1>
        
        <div class="report-metadata">
            <p><strong>Submitted by:</strong> security_researcher</p>
            <p><strong>Submitted at:</strong> 2025-01-15</p>
            <p><strong>Severity:</strong> Critical</p>
            <p><strong>Target URL:</strong> https://example.com/api/users/search</p>
        </div>
        
        <div class="report-description">
            <h2>Description</h2>
            <p>The user search API endpoint is vulnerable to SQL injection attacks. 
            The application directly concatenates user input into SQL queries without 
            proper sanitization or parameterization.</p>
        </div>
        
        <div class="report-steps">
            <h2>Steps to Reproduce</h2>
            <ol>
                <li>Navigate to https://example.com/api/users/search</li>
                <li>Send POST request with malicious query parameter</li>
                <li>Enter payload: ' OR '1'='1</li>
                <li>Observe database error revealing SQL injection vulnerability</li>
            </ol>
        </div>
        
        <div class="report-poc">
            <h2>Proof of Concept</h2>
            <pre><code>
curl -X POST https://example.com/api/users/search \
  -H 'Content-Type: application/json' \
  -d '{"query": "' OR '1'='1"}'
            </code></pre>
        </div>
        
        <div class="report-impact">
            <h2>Impact</h2>
            <p>An attacker can exploit this vulnerability to:</p>
            <ul>
                <li>Extract entire database contents including user credentials</li>
                <li>Modify or delete database records</li>
                <li>Bypass authentication mechanisms</li>
                <li>Potentially gain remote code execution on the database server</li>
            </ul>
        </div>
    </div>
</body>
</html>
"""
    
    # Write to file
    report_path = Path("test_html_report.html")
    report_path.write_text(html_content)
    return report_path


def create_sample_vulnerable_code():
    """Create sample vulnerable code for testing."""
    code_content = """
# File: app/api/user.py
# Vulnerable user search endpoint

from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.route('/api/users/search', methods=['POST'])
def search_users():
    data = request.get_json()
    query = data.get('query', '')
    
    # VULNERABLE: Direct string concatenation in SQL query
    sql = f"SELECT * FROM users WHERE username LIKE '%{query}%'"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(sql)  # SQL Injection vulnerability here
    results = cursor.fetchall()
    conn.close()
    
    return jsonify({'users': results})

if __name__ == '__main__':
    app.run(debug=True)
"""
    
    # Write to file
    code_path = Path("test_vulnerable_code.py")
    code_path.write_text(code_content)
    return code_path


def main():
    """Run HTML validation demo."""
    print("=" * 80)
    print("BountyBot - HTML Report Validation with Remediation Demo")
    print("=" * 80)
    print()
    
    # Create sample files
    print("[1/5] Creating sample HTML report...")
    report_path = create_sample_html_report()
    print(f"      Created: {report_path}")
    print()
    
    print("[2/5] Creating sample vulnerable code...")
    code_path = create_sample_vulnerable_code()
    print(f"      Created: {code_path}")
    print()
    
    # Load configuration
    print("[3/5] Loading configuration...")
    try:
        config = ConfigLoader.load_config()
        print("      Configuration loaded successfully")
    except Exception as e:
        print(f"      Error loading config: {e}")
        print("      Using default configuration")
        config = {
            'api': {
                'default_provider': 'anthropic',
                'providers': {
                    'anthropic': {
                        'api_key': 'test-key',
                        'model': 'claude-3-5-sonnet-20241022',
                        'max_tokens': 4096,
                        'temperature': 0.0
                    }
                }
            }
        }
    print()
    
    # Initialize orchestrator
    print("[4/5] Initializing orchestrator...")
    try:
        orchestrator = Orchestrator(config)
        print("      Orchestrator initialized with remediation engine")
    except Exception as e:
        print(f"      Error: {e}")
        return
    print()
    
    # Validate report
    print("[5/5] Validating HTML report...")
    print("      This will:")
    print("      - Parse HTML report from bug bounty platform")
    print("      - Perform AI-powered validation")
    print("      - Generate code fixes with diffs")
    print("      - Create WAF rules (ModSecurity, AWS WAF, Cloudflare)")
    print("      - Recommend compensating controls")
    print()
    
    try:
        result = orchestrator.validate_report(
            report_path=str(report_path),
            codebase_path=None,  # Would be actual codebase path in production
            target_url=None
        )
        
        print("=" * 80)
        print("VALIDATION RESULTS")
        print("=" * 80)
        print()
        
        print(f"Report Title: {result.report.title}")
        print(f"Verdict: {result.verdict.value}")
        print(f"Confidence: {result.confidence}%")
        print(f"Vulnerability Type: {result.report.vulnerability_type}")
        print(f"Severity: {result.report.severity.value if result.report.severity else 'Unknown'}")
        print()
        
        # Display remediation plan
        if result.remediation_plan:
            plan = result.remediation_plan
            
            print("=" * 80)
            print("REMEDIATION PLAN")
            print("=" * 80)
            print()
            
            # Code fixes
            if plan.code_fixes:
                print(f"CODE FIXES ({len(plan.code_fixes)} fixes)")
                print("-" * 80)
                for i, fix in enumerate(plan.code_fixes, 1):
                    print(f"\nFix #{i}:")
                    print(f"  File: {fix.file_path}")
                    if fix.line_number:
                        print(f"  Line: {fix.line_number}")
                    print(f"  Language: {fix.language}")
                    print(f"  Confidence: {fix.confidence:.0%}")
                    print(f"\n  Explanation:")
                    print(f"  {fix.explanation}")
                    if fix.diff:
                        print(f"\n  Diff:")
                        for line in fix.diff.split('\n')[:10]:  # Show first 10 lines
                            print(f"  {line}")
                print()
            
            # WAF rules
            if plan.waf_rules:
                print(f"WAF RULES ({len(plan.waf_rules)} rules)")
                print("-" * 80)
                for i, rule in enumerate(plan.waf_rules, 1):
                    print(f"\nRule #{i} - {rule.rule_type.upper()}")
                    print(f"  Description: {rule.description}")
                    print(f"  False Positive Risk: {rule.false_positive_risk}")
                    print(f"\n  Rule Content:")
                    for line in rule.rule_content.split('\n')[:15]:  # Show first 15 lines
                        print(f"  {line}")
                    print(f"\n  Testing Notes:")
                    print(f"  {rule.testing_notes}")
                print()
            
            # Compensating controls
            if plan.compensating_controls:
                print(f"COMPENSATING CONTROLS ({len(plan.compensating_controls)} controls)")
                print("-" * 80)
                for i, control in enumerate(plan.compensating_controls, 1):
                    print(f"\nControl #{i}: {control.control_type.upper()}")
                    print(f"  Description: {control.description}")
                    print(f"  Effectiveness: {control.effectiveness}")
                    print(f"\n  Implementation Steps:")
                    for step in control.implementation_steps:
                        print(f"    - {step}")
                    if control.limitations:
                        print(f"\n  Limitations:")
                        for limitation in control.limitations:
                            print(f"    - {limitation}")
                print()
            
            # Action items
            if plan.immediate_actions:
                print("IMMEDIATE ACTIONS")
                print("-" * 80)
                for action in plan.immediate_actions:
                    print(f"  - {action}")
                print()
            
            # Metadata
            print("REMEDIATION METADATA")
            print("-" * 80)
            print(f"  Estimated Effort: {plan.estimated_effort}")
            print(f"  Risk if Not Fixed: {plan.risk_if_not_fixed}")
            print()
        
        # Performance metrics
        print("=" * 80)
        print("PERFORMANCE METRICS")
        print("=" * 80)
        print(f"Processing Time: {result.processing_time_seconds:.2f}s")
        print(f"Total Cost: ${result.total_cost:.4f}")
        print(f"Cache Hits: {result.cache_hits}")
        print(f"Cache Misses: {result.cache_misses}")
        print()
        
        print("=" * 80)
        print("DEMO COMPLETE")
        print("=" * 80)
        print()
        print("Key Features Demonstrated:")
        print("  - HTML report parsing from bug bounty platforms")
        print("  - AI-powered vulnerability validation")
        print("  - Automated code fix generation with diffs")
        print("  - WAF rule generation (ModSecurity, AWS WAF, Cloudflare)")
        print("  - Compensating control recommendations")
        print("  - Efficient AI chunking for cost optimization")
        print()
        
    except Exception as e:
        print(f"Error during validation: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Cleanup
        print("Cleaning up test files...")
        if report_path.exists():
            report_path.unlink()
        if code_path.exists():
            code_path.unlink()
        print("Done!")


if __name__ == '__main__':
    main()

