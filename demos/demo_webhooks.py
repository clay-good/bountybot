"""
Demo script for BountyBot Webhook System.

This script demonstrates:
1. Creating webhooks
2. Listing webhooks
3. Updating webhooks
4. Testing webhook delivery
5. Viewing delivery logs
6. Deleting webhooks
"""

import requests
import json
import time
from typing import Dict, Any


# Configuration
API_BASE_URL = "http://localhost:8000"
API_KEY = "your-api-key-here"  # Replace with your admin API key

# Headers
HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}


def print_section(title: str):
    """Print section header."""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}\n")


def print_json(data: Dict[str, Any]):
    """Pretty print JSON data."""
    print(json.dumps(data, indent=2))


def create_webhook():
    """Create a new webhook."""
    print_section("1. Creating Webhook")
    
    webhook_data = {
        "url": "https://webhook.site/unique-id",  # Replace with your webhook URL
        "events": [
            "validation.completed",
            "validation.failed",
            "critical_issue.found"
        ],
        "description": "Demo webhook for testing"
    }
    
    print("Creating webhook with data:")
    print_json(webhook_data)
    
    response = requests.post(
        f"{API_BASE_URL}/webhooks",
        headers=HEADERS,
        json=webhook_data
    )
    
    if response.status_code == 200:
        webhook = response.json()
        print("\n✅ Webhook created successfully!")
        print_json(webhook)
        return webhook
    else:
        print(f"\n❌ Error creating webhook: {response.status_code}")
        print(response.text)
        return None


def list_webhooks():
    """List all webhooks."""
    print_section("2. Listing Webhooks")
    
    response = requests.get(
        f"{API_BASE_URL}/webhooks",
        headers=HEADERS
    )
    
    if response.status_code == 200:
        webhooks = response.json()
        print(f"Found {len(webhooks)} webhook(s):")
        print_json(webhooks)
        return webhooks
    else:
        print(f"❌ Error listing webhooks: {response.status_code}")
        print(response.text)
        return []


def get_webhook(webhook_id: str):
    """Get webhook by ID."""
    print_section(f"3. Getting Webhook: {webhook_id}")
    
    response = requests.get(
        f"{API_BASE_URL}/webhooks/{webhook_id}",
        headers=HEADERS
    )
    
    if response.status_code == 200:
        webhook = response.json()
        print("✅ Webhook details:")
        print_json(webhook)
        return webhook
    else:
        print(f"❌ Error getting webhook: {response.status_code}")
        print(response.text)
        return None


def update_webhook(webhook_id: str):
    """Update webhook configuration."""
    print_section(f"4. Updating Webhook: {webhook_id}")
    
    update_data = {
        "description": "Updated demo webhook",
        "events": [
            "validation.completed",
            "validation.failed",
            "critical_issue.found",
            "duplicate.detected"
        ]
    }
    
    print("Updating webhook with data:")
    print_json(update_data)
    
    response = requests.patch(
        f"{API_BASE_URL}/webhooks/{webhook_id}",
        headers=HEADERS,
        json=update_data
    )
    
    if response.status_code == 200:
        webhook = response.json()
        print("\n✅ Webhook updated successfully!")
        print_json(webhook)
        return webhook
    else:
        print(f"\n❌ Error updating webhook: {response.status_code}")
        print(response.text)
        return None


def test_webhook(webhook_id: str):
    """Send test event to webhook."""
    print_section(f"5. Testing Webhook: {webhook_id}")
    
    print("Sending test event...")
    
    response = requests.post(
        f"{API_BASE_URL}/webhooks/{webhook_id}/test",
        headers=HEADERS
    )
    
    if response.status_code == 200:
        result = response.json()
        print("✅ Test event sent successfully!")
        print_json(result)
        return True
    else:
        print(f"❌ Error sending test event: {response.status_code}")
        print(response.text)
        return False


def list_deliveries(webhook_id: str):
    """List webhook deliveries."""
    print_section(f"6. Listing Deliveries for Webhook: {webhook_id}")
    
    response = requests.get(
        f"{API_BASE_URL}/webhooks/{webhook_id}/deliveries",
        headers=HEADERS,
        params={"limit": 10}
    )
    
    if response.status_code == 200:
        deliveries = response.json()
        print(f"Found {len(deliveries)} delivery(ies):")
        print_json(deliveries)
        return deliveries
    else:
        print(f"❌ Error listing deliveries: {response.status_code}")
        print(response.text)
        return []


def trigger_validation():
    """Trigger a validation to test webhook delivery."""
    print_section("7. Triggering Validation (to test webhook)")
    
    report_data = {
        "report": {
            "title": "SQL Injection in Login Form",
            "description": "The login form is vulnerable to SQL injection attacks.",
            "vulnerability_type": "SQL Injection",
            "severity": "CRITICAL",
            "affected_url": "https://example.com/login",
            "steps_to_reproduce": [
                "Navigate to login page",
                "Enter ' OR '1'='1 in username field",
                "Click login"
            ],
            "proof_of_concept": "Username: ' OR '1'='1\nPassword: anything",
            "impact": "Attacker can bypass authentication and access any account.",
            "researcher_id": "demo-researcher",
            "researcher_username": "demo_user"
        }
    }
    
    print("Submitting validation request...")
    print_json(report_data)
    
    response = requests.post(
        f"{API_BASE_URL}/validate",
        headers=HEADERS,
        json=report_data
    )
    
    if response.status_code == 200:
        result = response.json()
        print("\n✅ Validation completed!")
        print_json(result)
        print("\n⏳ Webhook should be triggered in the background...")
        return result
    else:
        print(f"\n❌ Error triggering validation: {response.status_code}")
        print(response.text)
        return None


def delete_webhook(webhook_id: str):
    """Delete webhook."""
    print_section(f"8. Deleting Webhook: {webhook_id}")
    
    response = requests.delete(
        f"{API_BASE_URL}/webhooks/{webhook_id}",
        headers=HEADERS
    )
    
    if response.status_code == 200:
        result = response.json()
        print("✅ Webhook deleted successfully!")
        print_json(result)
        return True
    else:
        print(f"❌ Error deleting webhook: {response.status_code}")
        print(response.text)
        return False


def main():
    """Run webhook demo."""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                    BountyBot Webhook System Demo                             ║
║                                                                              ║
║  This demo showcases the webhook system for event-driven notifications.     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Check if API key is set
    if API_KEY == "your-api-key-here":
        print("⚠️  Please set your API key in the script before running!")
        print("   You can create an API key using: POST /admin/keys")
        return
    
    try:
        # 1. Create webhook
        webhook = create_webhook()
        if not webhook:
            return
        
        webhook_id = webhook['webhook_id']
        
        # 2. List webhooks
        time.sleep(1)
        list_webhooks()
        
        # 3. Get webhook details
        time.sleep(1)
        get_webhook(webhook_id)
        
        # 4. Update webhook
        time.sleep(1)
        update_webhook(webhook_id)
        
        # 5. Test webhook
        time.sleep(1)
        test_webhook(webhook_id)
        
        # 6. Wait for delivery
        time.sleep(2)
        list_deliveries(webhook_id)
        
        # 7. Trigger validation (optional)
        print("\n⏸️  Would you like to trigger a validation to test webhook delivery?")
        print("   This will send a real validation request and trigger webhooks.")
        user_input = input("   Continue? (y/n): ")
        
        if user_input.lower() == 'y':
            trigger_validation()
            time.sleep(3)
            list_deliveries(webhook_id)
        
        # 8. Delete webhook (optional)
        print("\n⏸️  Would you like to delete the demo webhook?")
        user_input = input("   Delete? (y/n): ")
        
        if user_input.lower() == 'y':
            delete_webhook(webhook_id)
        
        print_section("Demo Complete!")
        print("✅ Webhook system demo completed successfully!")
        print("\nNext steps:")
        print("  1. Check your webhook URL for received events")
        print("  2. Integrate webhooks with your systems (Slack, JIRA, etc.)")
        print("  3. Monitor delivery logs for troubleshooting")
        print("  4. Configure retry settings for reliability")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error during demo: {e}")


if __name__ == "__main__":
    main()

