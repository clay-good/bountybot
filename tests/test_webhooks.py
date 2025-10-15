import unittest
import asyncio
import json
import tempfile
import os
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime

from bountybot.webhooks import (
    WebhookManager,
    WebhookDispatcher,
    Webhook,
    WebhookDelivery,
    WebhookEvent,
    DeliveryStatus
)


class TestWebhookManager(unittest.TestCase):
    """Test webhook manager."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create temporary storage file
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        self.temp_file.close()
        self.manager = WebhookManager(storage_path=self.temp_file.name)
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)
    
    def test_create_webhook(self):
        """Test webhook creation."""
        webhook = self.manager.create_webhook(
            url="https://example.com/webhook",
            events=["validation.completed", "validation.failed"],
            description="Test webhook"
        )
        
        self.assertIsNotNone(webhook)
        self.assertTrue(webhook.webhook_id.startswith("wh_"))
        self.assertEqual(webhook.url, "https://example.com/webhook")
        self.assertEqual(len(webhook.events), 2)
        self.assertTrue(webhook.secret.startswith("whsec_"))
        self.assertEqual(webhook.status, "active")
    
    def test_create_webhook_invalid_event(self):
        """Test webhook creation with invalid event."""
        with self.assertRaises(ValueError):
            self.manager.create_webhook(
                url="https://example.com/webhook",
                events=["invalid.event"]
            )
    
    def test_get_webhook(self):
        """Test getting webhook by ID."""
        webhook = self.manager.create_webhook(
            url="https://example.com/webhook",
            events=["validation.completed"]
        )
        
        retrieved = self.manager.get_webhook(webhook.webhook_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.webhook_id, webhook.webhook_id)
        self.assertEqual(retrieved.url, webhook.url)
    
    def test_get_webhook_not_found(self):
        """Test getting non-existent webhook."""
        webhook = self.manager.get_webhook("wh_nonexistent")
        self.assertIsNone(webhook)
    
    def test_list_webhooks(self):
        """Test listing webhooks."""
        webhook1 = self.manager.create_webhook(
            url="https://example.com/webhook1",
            events=["validation.completed"]
        )
        webhook2 = self.manager.create_webhook(
            url="https://example.com/webhook2",
            events=["validation.failed"]
        )
        
        webhooks = self.manager.list_webhooks()
        self.assertEqual(len(webhooks), 2)
    
    def test_list_webhooks_by_status(self):
        """Test listing webhooks by status."""
        webhook1 = self.manager.create_webhook(
            url="https://example.com/webhook1",
            events=["validation.completed"]
        )
        webhook2 = self.manager.create_webhook(
            url="https://example.com/webhook2",
            events=["validation.failed"]
        )
        
        # Update webhook2 status
        self.manager.update_webhook(webhook2.webhook_id, status="inactive")
        
        active_webhooks = self.manager.list_webhooks(status="active")
        self.assertEqual(len(active_webhooks), 1)
        self.assertEqual(active_webhooks[0].webhook_id, webhook1.webhook_id)
    
    def test_list_webhooks_by_event(self):
        """Test listing webhooks by event."""
        webhook1 = self.manager.create_webhook(
            url="https://example.com/webhook1",
            events=["validation.completed", "validation.failed"]
        )
        webhook2 = self.manager.create_webhook(
            url="https://example.com/webhook2",
            events=["validation.failed"]
        )
        
        webhooks = self.manager.list_webhooks(event="validation.completed")
        self.assertEqual(len(webhooks), 1)
        self.assertEqual(webhooks[0].webhook_id, webhook1.webhook_id)
    
    def test_update_webhook(self):
        """Test updating webhook."""
        webhook = self.manager.create_webhook(
            url="https://example.com/webhook",
            events=["validation.completed"]
        )
        
        updated = self.manager.update_webhook(
            webhook.webhook_id,
            url="https://example.com/new-webhook",
            events=["validation.completed", "validation.failed"],
            status="inactive",
            description="Updated webhook"
        )
        
        self.assertIsNotNone(updated)
        self.assertEqual(updated.url, "https://example.com/new-webhook")
        self.assertEqual(len(updated.events), 2)
        self.assertEqual(updated.status, "inactive")
        self.assertEqual(updated.description, "Updated webhook")
    
    def test_update_webhook_not_found(self):
        """Test updating non-existent webhook."""
        updated = self.manager.update_webhook("wh_nonexistent", url="https://example.com/webhook")
        self.assertIsNone(updated)
    
    def test_delete_webhook(self):
        """Test deleting webhook."""
        webhook = self.manager.create_webhook(
            url="https://example.com/webhook",
            events=["validation.completed"]
        )
        
        success = self.manager.delete_webhook(webhook.webhook_id)
        self.assertTrue(success)
        
        retrieved = self.manager.get_webhook(webhook.webhook_id)
        self.assertIsNone(retrieved)
    
    def test_delete_webhook_not_found(self):
        """Test deleting non-existent webhook."""
        success = self.manager.delete_webhook("wh_nonexistent")
        self.assertFalse(success)
    
    def test_generate_signature(self):
        """Test signature generation."""
        webhook = self.manager.create_webhook(
            url="https://example.com/webhook",
            events=["validation.completed"]
        )
        
        payload = '{"test": "data"}'
        signature = self.manager.generate_signature(webhook, payload)
        
        self.assertIsNotNone(signature)
        self.assertTrue(signature.startswith("sha256="))
    
    def test_verify_signature(self):
        """Test signature verification."""
        webhook = self.manager.create_webhook(
            url="https://example.com/webhook",
            events=["validation.completed"]
        )
        
        payload = '{"test": "data"}'
        signature = self.manager.generate_signature(webhook, payload)
        
        # Valid signature
        self.assertTrue(self.manager.verify_signature(webhook, payload, signature))
        
        # Invalid signature
        self.assertFalse(self.manager.verify_signature(webhook, payload, "sha256=invalid"))
    
    def test_record_delivery(self):
        """Test recording delivery."""
        delivery = WebhookDelivery(
            delivery_id="del_test",
            webhook_id="wh_test",
            event_type="validation.completed",
            payload={"test": "data"}
        )
        
        self.manager.record_delivery(delivery)
        
        retrieved = self.manager.get_delivery("del_test")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.delivery_id, "del_test")
    
    def test_list_deliveries(self):
        """Test listing deliveries."""
        delivery1 = WebhookDelivery(
            delivery_id="del_1",
            webhook_id="wh_test",
            event_type="validation.completed",
            payload={"test": "data1"}
        )
        delivery2 = WebhookDelivery(
            delivery_id="del_2",
            webhook_id="wh_test",
            event_type="validation.failed",
            payload={"test": "data2"}
        )
        
        self.manager.record_delivery(delivery1)
        self.manager.record_delivery(delivery2)
        
        deliveries = self.manager.list_deliveries()
        self.assertEqual(len(deliveries), 2)
    
    def test_persistence(self):
        """Test webhook persistence."""
        webhook = self.manager.create_webhook(
            url="https://example.com/webhook",
            events=["validation.completed"],
            description="Test webhook"
        )
        
        # Create new manager with same storage
        new_manager = WebhookManager(storage_path=self.temp_file.name)
        
        retrieved = new_manager.get_webhook(webhook.webhook_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.url, webhook.url)
        self.assertEqual(retrieved.description, webhook.description)


class TestWebhookDispatcher(unittest.TestCase):
    """Test webhook dispatcher."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        self.temp_file.close()
        self.manager = WebhookManager(storage_path=self.temp_file.name)
        self.dispatcher = WebhookDispatcher(self.manager, timeout=5, max_retries=3)
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)
    
    def test_dispatch_event_no_webhooks(self):
        """Test dispatching event with no webhooks."""
        async def run_test():
            await self.dispatcher.dispatch_event(
                "validation.completed",
                {"test": "data"}
            )
        
        asyncio.run(run_test())
        # Should complete without error
    
    @patch('httpx.AsyncClient.post')
    def test_dispatch_event_success(self, mock_post):
        """Test successful event dispatch."""
        # Create webhook
        webhook = self.manager.create_webhook(
            url="https://example.com/webhook",
            events=["validation.completed"]
        )
        
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "OK"
        mock_post.return_value = mock_response
        
        async def run_test():
            await self.dispatcher.dispatch_event(
                "validation.completed",
                {"test": "data"}
            )
        
        asyncio.run(run_test())
        
        # Verify webhook was called
        self.assertTrue(mock_post.called)
        
        # Verify delivery was recorded
        deliveries = self.manager.list_deliveries(webhook_id=webhook.webhook_id)
        self.assertEqual(len(deliveries), 1)
        self.assertEqual(deliveries[0].status, DeliveryStatus.SUCCESS)


if __name__ == '__main__':
    unittest.main()

