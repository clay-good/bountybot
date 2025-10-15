import requests
import json
import time
from typing import Dict, Any


# API Configuration
API_BASE_URL = "http://localhost:8000"
API_KEY = "test_key_12345"  # Replace with your actual API key

# Headers with authentication
HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}


def print_section(title: str):
    """Print a section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def print_response(response: requests.Response):
    """Print API response."""
    print(f"Status Code: {response.status_code}")
    print(f"Response:")
    print(json.dumps(response.json(), indent=2))


def demo_health_check():
    """Demonstrate health check endpoint."""
    print_section("1. Health Check")
    
    response = requests.get(f"{API_BASE_URL}/health")
    print_response(response)
    
    if response.status_code == 200:
        data = response.json()
        print(f"\n✓ Service Status: {data['status']}")
        print(f"✓ Database Connected: {data['database_connected']}")
        print(f"✓ AI Provider Available: {data['ai_provider_available']}")


def demo_single_validation():
    """Demonstrate single report validation."""
    print_section("2. Single Report Validation")
    
    # Sample vulnerability report
    report = {
        "report": {
            "title": "SQL Injection in Login Form",
            "description": "The login form at /login is vulnerable to SQL injection. By entering a single quote in the username field, the application returns a database error, indicating that user input is not properly sanitized before being used in SQL queries.",
            "vulnerability_type": "SQL Injection",
            "severity": "HIGH",
            "affected_url": "https://example.com/login",
            "steps_to_reproduce": "1. Navigate to https://example.com/login\n2. Enter ' OR '1'='1 in the username field\n3. Enter any password\n4. Click 'Login'\n5. Observe database error message",
            "proof_of_concept": "username: ' OR '1'='1 --\npassword: anything",
            "impact": "An attacker can bypass authentication and gain unauthorized access to user accounts, potentially accessing sensitive data or performing unauthorized actions.",
            "researcher_id": "researcher_123",
            "researcher_username": "security_researcher"
        },
        "options": {
            "enable_code_analysis": False,
            "skip_duplicate_check": False
        }
    }
    
    print("Sending validation request...")
    print(f"Report: {report['report']['title']}")
    
    response = requests.post(
        f"{API_BASE_URL}/validate",
        headers=HEADERS,
        json=report
    )
    
    print_response(response)
    
    if response.status_code == 200:
        data = response.json()
        result = data.get('result', {})
        
        print(f"\n✓ Request ID: {data['request_id']}")
        print(f"✓ Verdict: {result.get('verdict')}")
        print(f"✓ Confidence: {result.get('confidence')}%")
        print(f"✓ CVSS Score: {result.get('cvss_score')}")
        print(f"✓ Priority: {result.get('priority_level')} (Score: {result.get('priority_score')})")
        print(f"✓ Is Duplicate: {result.get('is_duplicate')}")
        print(f"✓ Is False Positive: {result.get('is_false_positive')}")
        
        if result.get('findings'):
            print(f"\nFindings:")
            for finding in result['findings']:
                print(f"  - {finding}")
        
        if result.get('recommendations'):
            print(f"\nRecommendations:")
            for rec in result['recommendations']:
                print(f"  - {rec}")


def demo_batch_validation():
    """Demonstrate batch validation."""
    print_section("3. Batch Validation")
    
    # Sample batch of reports
    batch = {
        "reports": [
            {
                "title": "XSS in Search Field",
                "description": "The search field is vulnerable to reflected XSS. User input is not sanitized before being displayed in the search results page.",
                "vulnerability_type": "XSS",
                "severity": "MEDIUM",
                "affected_url": "https://example.com/search",
                "proof_of_concept": "<script>alert('XSS')</script>"
            },
            {
                "title": "CSRF in Profile Update",
                "description": "The profile update endpoint does not validate CSRF tokens, allowing attackers to perform unauthorized profile updates.",
                "vulnerability_type": "CSRF",
                "severity": "MEDIUM",
                "affected_url": "https://example.com/profile/update"
            },
            {
                "title": "Information Disclosure in Error Messages",
                "description": "Error messages reveal sensitive information about the application's internal structure and database schema.",
                "vulnerability_type": "Information Disclosure",
                "severity": "LOW",
                "affected_url": "https://example.com/api/users"
            }
        ],
        "options": {
            "skip_duplicate_check": False
        }
    }
    
    print(f"Sending batch validation request with {len(batch['reports'])} reports...")
    
    response = requests.post(
        f"{API_BASE_URL}/validate/batch",
        headers=HEADERS,
        json=batch
    )
    
    print_response(response)
    
    if response.status_code == 200:
        data = response.json()
        
        print(f"\n✓ Batch ID: {data['batch_id']}")
        print(f"✓ Total Reports: {data['total_reports']}")
        print(f"✓ Completed: {data['completed']}")
        print(f"✓ Failed: {data['failed']}")
        
        print(f"\nResults Summary:")
        for i, result_data in enumerate(data['results'], 1):
            result = result_data.get('result', {})
            print(f"\n  Report {i}:")
            print(f"    Verdict: {result.get('verdict')}")
            print(f"    Confidence: {result.get('confidence')}%")
            print(f"    Priority: {result.get('priority_level')}")


def demo_metrics():
    """Demonstrate metrics endpoint."""
    print_section("4. API Metrics")
    
    response = requests.get(
        f"{API_BASE_URL}/metrics",
        headers=HEADERS
    )
    
    print_response(response)
    
    if response.status_code == 200:
        data = response.json()
        
        print(f"\n✓ Total Requests: {data['total_requests']}")
        print(f"✓ Successful Requests: {data['successful_requests']}")
        print(f"✓ Failed Requests: {data['failed_requests']}")
        print(f"✓ Average Response Time: {data['average_response_time']:.3f}s")
        print(f"✓ Total Reports Validated: {data['total_reports_validated']}")
        print(f"✓ Valid Reports: {data['valid_reports']}")
        print(f"✓ Invalid Reports: {data['invalid_reports']}")
        print(f"✓ Duplicate Reports: {data['duplicate_reports']}")
        print(f"✓ False Positive Reports: {data['false_positive_reports']}")
        print(f"✓ Total AI Cost: ${data['total_ai_cost']:.2f}")
        print(f"✓ Cache Hit Rate: {data['cache_hit_rate']:.1%}")


def demo_admin_operations():
    """Demonstrate admin operations."""
    print_section("5. Admin Operations (API Key Management)")
    
    # List API keys
    print("Listing API keys...")
    response = requests.get(
        f"{API_BASE_URL}/admin/keys",
        headers=HEADERS
    )
    
    if response.status_code == 200:
        data = response.json()
        print(f"\n✓ Total API Keys: {len(data['keys'])}")
        
        for key in data['keys']:
            print(f"\n  Key ID: {key['key_id']}")
            print(f"  Name: {key['name']}")
            print(f"  Rate Limit: {key['rate_limit']} req/min")
            print(f"  Active: {key['is_active']}")
            print(f"  Request Count: {key['request_count']}")
    else:
        print(f"✗ Failed to list keys: {response.status_code}")
        print("  (This requires admin privileges)")


def main():
    """Run all demos."""
    print("\n" + "=" * 80)
    print("  BountyBot REST API Demo")
    print("=" * 80)
    print(f"\nAPI Base URL: {API_BASE_URL}")
    print(f"API Key: {API_KEY[:10]}...")
    print("\nMake sure the API server is running:")
    print("  bountybot-api --host 0.0.0.0 --port 8000")
    print("\n" + "=" * 80)
    
    try:
        # Run demos
        demo_health_check()
        time.sleep(1)
        
        demo_single_validation()
        time.sleep(1)
        
        demo_batch_validation()
        time.sleep(1)
        
        demo_metrics()
        time.sleep(1)
        
        demo_admin_operations()
        
        print("\n" + "=" * 80)
        print("  Demo Complete!")
        print("=" * 80)
        print("\nFor more information, visit:")
        print(f"  - API Documentation: {API_BASE_URL}/docs")
        print(f"  - ReDoc: {API_BASE_URL}/redoc")
        print("\n")
        
    except requests.exceptions.ConnectionError:
        print("\n✗ Error: Could not connect to API server")
        print("  Make sure the server is running:")
        print("    bountybot-api --host 0.0.0.0 --port 8000")
    except Exception as e:
        print(f"\n✗ Error: {e}")


if __name__ == "__main__":
    main()

