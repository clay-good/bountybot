import json
import time
import asyncio
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import httpx

from .webhook_manager import (
    WebhookManager,
    Webhook,
    WebhookDelivery,
    WebhookEvent,
    DeliveryStatus
)

logger = logging.getLogger(__name__)


class WebhookDispatcher:
    """
    Dispatches webhook events to registered endpoints.
    
    Features:
    - Async HTTP delivery
    - Retry logic with exponential backoff
    - Signature generation
    - Delivery tracking
    - Failure handling
    - Timeout management
    """
    
    def __init__(
        self,
        webhook_manager: WebhookManager,
        timeout: int = 30,
        max_retries: int = 5,
        initial_retry_delay: int = 60
    ):
        """
        Initialize webhook dispatcher.
        
        Args:
            webhook_manager: Webhook manager instance
            timeout: HTTP request timeout in seconds
            max_retries: Maximum retry attempts
            initial_retry_delay: Initial retry delay in seconds
        """
        self.webhook_manager = webhook_manager
        self.timeout = timeout
        self.max_retries = max_retries
        self.initial_retry_delay = initial_retry_delay
        self.client = httpx.AsyncClient(timeout=timeout)
    
    async def dispatch_event(
        self,
        event_type: str,
        payload: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Dispatch event to all subscribed webhooks.
        
        Args:
            event_type: Event type (e.g., "validation.completed")
            payload: Event payload
            metadata: Optional metadata
        """
        # Get webhooks subscribed to this event
        webhooks = self.webhook_manager.list_webhooks(
            status="active",
            event=event_type
        )
        
        if not webhooks:
            logger.debug(f"No webhooks subscribed to {event_type}")
            return
        
        logger.info(f"Dispatching {event_type} to {len(webhooks)} webhooks")
        
        # Dispatch to all webhooks concurrently
        tasks = [
            self._deliver_webhook(webhook, event_type, payload, metadata)
            for webhook in webhooks
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _deliver_webhook(
        self,
        webhook: Webhook,
        event_type: str,
        payload: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Deliver webhook to a single endpoint.
        
        Args:
            webhook: Webhook configuration
            event_type: Event type
            payload: Event payload
            metadata: Optional metadata
        """
        # Create delivery record
        delivery = WebhookDelivery(
            delivery_id=f"del_{int(time.time() * 1000)}_{webhook.webhook_id[:8]}",
            webhook_id=webhook.webhook_id,
            event_type=event_type,
            payload=payload,
            max_attempts=self.max_retries
        )
        
        self.webhook_manager.record_delivery(delivery)
        
        # Attempt delivery with retries
        for attempt in range(self.max_retries):
            delivery.attempt_count = attempt + 1
            
            try:
                success = await self._attempt_delivery(webhook, delivery, event_type, payload, metadata)
                
                if success:
                    delivery.status = DeliveryStatus.SUCCESS
                    delivery.delivered_at = datetime.utcnow().isoformat()
                    
                    # Update webhook stats
                    webhook.delivery_count += 1
                    webhook.last_delivery_at = delivery.delivered_at
                    self.webhook_manager._save_webhooks()
                    
                    logger.info(f"Webhook delivered successfully: {webhook.webhook_id}")
                    return
                
            except Exception as e:
                logger.error(f"Webhook delivery error: {e}")
                delivery.error_message = str(e)
            
            # Calculate retry delay with exponential backoff
            if attempt < self.max_retries - 1:
                delay = self.initial_retry_delay * (2 ** attempt)
                delivery.status = DeliveryStatus.RETRYING
                delivery.next_retry_at = (
                    datetime.utcnow() + timedelta(seconds=delay)
                ).isoformat()
                
                logger.warning(
                    f"Webhook delivery failed, retrying in {delay}s "
                    f"(attempt {attempt + 1}/{self.max_retries})"
                )
                
                await asyncio.sleep(delay)
        
        # All retries failed
        delivery.status = DeliveryStatus.FAILED
        webhook.failure_count += 1
        
        # Disable webhook after too many failures
        if webhook.failure_count >= 10:
            webhook.status = "failed"
            logger.error(f"Webhook disabled due to repeated failures: {webhook.webhook_id}")
        
        self.webhook_manager._save_webhooks()
        logger.error(f"Webhook delivery failed after {self.max_retries} attempts")
    
    async def _attempt_delivery(
        self,
        webhook: Webhook,
        delivery: WebhookDelivery,
        event_type: str,
        payload: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Attempt single webhook delivery.
        
        Args:
            webhook: Webhook configuration
            delivery: Delivery record
            event_type: Event type
            payload: Event payload
            metadata: Optional metadata
            
        Returns:
            True if successful, False otherwise
        """
        # Prepare webhook payload
        webhook_payload = {
            "event": event_type,
            "delivery_id": delivery.delivery_id,
            "timestamp": datetime.utcnow().isoformat(),
            "data": payload
        }
        
        if metadata:
            webhook_payload["metadata"] = metadata
        
        # Serialize payload
        payload_json = json.dumps(webhook_payload)
        
        # Generate signature
        signature = self.webhook_manager.generate_signature(webhook, payload_json)
        
        # Prepare headers
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "BountyBot-Webhook/1.0",
            "X-Webhook-Signature": signature,
            "X-Webhook-Event": event_type,
            "X-Webhook-Delivery": delivery.delivery_id,
            "X-Webhook-ID": webhook.webhook_id,
            **webhook.headers
        }
        
        # Send HTTP POST request
        try:
            response = await self.client.post(
                webhook.url,
                content=payload_json,
                headers=headers
            )
            
            delivery.response_code = response.status_code
            delivery.response_body = response.text[:1000]  # Limit response body size
            
            # Consider 2xx status codes as success
            if 200 <= response.status_code < 300:
                return True
            else:
                delivery.error_message = f"HTTP {response.status_code}: {response.text[:200]}"
                return False
                
        except httpx.TimeoutException:
            delivery.error_message = f"Request timeout after {self.timeout}s"
            return False
        except httpx.RequestError as e:
            delivery.error_message = f"Request error: {str(e)}"
            return False
        except Exception as e:
            delivery.error_message = f"Unexpected error: {str(e)}"
            return False
    
    async def retry_failed_deliveries(self, webhook_id: Optional[str] = None):
        """
        Retry failed webhook deliveries.
        
        Args:
            webhook_id: Optional webhook ID to filter by
        """
        failed_deliveries = self.webhook_manager.list_deliveries(
            webhook_id=webhook_id,
            status=DeliveryStatus.FAILED
        )
        
        logger.info(f"Retrying {len(failed_deliveries)} failed deliveries")
        
        for delivery in failed_deliveries:
            webhook = self.webhook_manager.get_webhook(delivery.webhook_id)
            if not webhook or webhook.status != "active":
                continue
            
            # Reset delivery for retry
            delivery.status = DeliveryStatus.PENDING
            delivery.attempt_count = 0
            delivery.error_message = None
            
            await self._deliver_webhook(
                webhook,
                delivery.event_type,
                delivery.payload,
                None
            )
    
    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()

    def __del__(self):
        """Cleanup on deletion."""
        try:
            # Check if there's a running event loop
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Schedule the close coroutine
                asyncio.create_task(self.close())
            else:
                # Run the close coroutine synchronously
                loop.run_until_complete(self.close())
        except Exception:
            # Silently ignore cleanup errors
            pass

