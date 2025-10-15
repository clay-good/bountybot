import json
import uuid
import hashlib
import hmac
from datetime import datetime
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field, asdict
from enum import Enum


class WebhookEvent(str, Enum):
    """Webhook event types."""
    VALIDATION_STARTED = "validation.started"
    VALIDATION_COMPLETED = "validation.completed"
    VALIDATION_FAILED = "validation.failed"
    REPORT_CREATED = "report.created"
    REPORT_UPDATED = "report.updated"
    PRIORITY_CHANGED = "priority.changed"
    DUPLICATE_DETECTED = "duplicate.detected"
    FALSE_POSITIVE_DETECTED = "false_positive.detected"
    CRITICAL_ISSUE_FOUND = "critical_issue.found"


class WebhookStatus(str, Enum):
    """Webhook status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    FAILED = "failed"


class DeliveryStatus(str, Enum):
    """Webhook delivery status."""
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    RETRYING = "retrying"


@dataclass
class Webhook:
    """Webhook configuration."""
    
    webhook_id: str
    url: str
    events: List[str]
    secret: str
    status: str = WebhookStatus.ACTIVE
    description: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_delivery_at: Optional[str] = None
    delivery_count: int = 0
    failure_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Webhook':
        """Create from dictionary."""
        return cls(**data)


@dataclass
class WebhookDelivery:
    """Webhook delivery record."""
    
    delivery_id: str
    webhook_id: str
    event_type: str
    payload: Dict[str, Any]
    status: str = DeliveryStatus.PENDING
    response_code: Optional[int] = None
    response_body: Optional[str] = None
    error_message: Optional[str] = None
    attempt_count: int = 0
    max_attempts: int = 5
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    delivered_at: Optional[str] = None
    next_retry_at: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WebhookDelivery':
        """Create from dictionary."""
        return cls(**data)


class WebhookManager:
    """
    Manages webhook registrations and deliveries.
    
    Features:
    - Webhook CRUD operations
    - Event subscription management
    - Signature generation for security
    - Delivery tracking
    - Failure handling
    """
    
    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialize webhook manager.
        
        Args:
            storage_path: Path to store webhook data (JSON file)
        """
        self.storage_path = storage_path or "webhooks.json"
        self.webhooks: Dict[str, Webhook] = {}
        self.deliveries: Dict[str, WebhookDelivery] = {}
        self._load_webhooks()
    
    def create_webhook(
        self,
        url: str,
        events: List[str],
        description: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Webhook:
        """
        Create a new webhook.
        
        Args:
            url: Webhook URL
            events: List of event types to subscribe to
            description: Optional description
            headers: Optional custom headers
            
        Returns:
            Created webhook
        """
        # Validate events
        valid_events = [e.value for e in WebhookEvent]
        for event in events:
            if event not in valid_events:
                raise ValueError(f"Invalid event type: {event}")
        
        # Generate webhook ID and secret
        webhook_id = f"wh_{uuid.uuid4().hex[:16]}"
        secret = f"whsec_{uuid.uuid4().hex}"
        
        webhook = Webhook(
            webhook_id=webhook_id,
            url=url,
            events=events,
            secret=secret,
            description=description,
            headers=headers or {}
        )
        
        self.webhooks[webhook_id] = webhook
        self._save_webhooks()
        
        return webhook
    
    def get_webhook(self, webhook_id: str) -> Optional[Webhook]:
        """Get webhook by ID."""
        return self.webhooks.get(webhook_id)
    
    def list_webhooks(
        self,
        status: Optional[str] = None,
        event: Optional[str] = None
    ) -> List[Webhook]:
        """
        List webhooks with optional filtering.
        
        Args:
            status: Filter by status
            event: Filter by event type
            
        Returns:
            List of webhooks
        """
        webhooks = list(self.webhooks.values())
        
        if status:
            webhooks = [w for w in webhooks if w.status == status]
        
        if event:
            webhooks = [w for w in webhooks if event in w.events]
        
        return webhooks
    
    def update_webhook(
        self,
        webhook_id: str,
        url: Optional[str] = None,
        events: Optional[List[str]] = None,
        status: Optional[str] = None,
        description: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Optional[Webhook]:
        """
        Update webhook configuration.
        
        Args:
            webhook_id: Webhook ID
            url: New URL
            events: New event list
            status: New status
            description: New description
            headers: New headers
            
        Returns:
            Updated webhook or None if not found
        """
        webhook = self.webhooks.get(webhook_id)
        if not webhook:
            return None
        
        if url:
            webhook.url = url
        if events:
            webhook.events = events
        if status:
            webhook.status = status
        if description is not None:
            webhook.description = description
        if headers is not None:
            webhook.headers = headers
        
        webhook.updated_at = datetime.utcnow().isoformat()
        self._save_webhooks()
        
        return webhook
    
    def delete_webhook(self, webhook_id: str) -> bool:
        """
        Delete webhook.
        
        Args:
            webhook_id: Webhook ID
            
        Returns:
            True if deleted, False if not found
        """
        if webhook_id in self.webhooks:
            del self.webhooks[webhook_id]
            self._save_webhooks()
            return True
        return False
    
    def generate_signature(self, webhook: Webhook, payload: str) -> str:
        """
        Generate HMAC signature for webhook payload.
        
        Args:
            webhook: Webhook configuration
            payload: JSON payload string
            
        Returns:
            HMAC signature
        """
        signature = hmac.new(
            webhook.secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"sha256={signature}"
    
    def verify_signature(self, webhook: Webhook, payload: str, signature: str) -> bool:
        """
        Verify webhook signature.
        
        Args:
            webhook: Webhook configuration
            payload: JSON payload string
            signature: Signature to verify
            
        Returns:
            True if valid, False otherwise
        """
        expected = self.generate_signature(webhook, payload)
        return hmac.compare_digest(expected, signature)
    
    def record_delivery(self, delivery: WebhookDelivery):
        """Record webhook delivery."""
        self.deliveries[delivery.delivery_id] = delivery
    
    def get_delivery(self, delivery_id: str) -> Optional[WebhookDelivery]:
        """Get delivery by ID."""
        return self.deliveries.get(delivery_id)
    
    def list_deliveries(
        self,
        webhook_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100
    ) -> List[WebhookDelivery]:
        """
        List webhook deliveries.
        
        Args:
            webhook_id: Filter by webhook ID
            status: Filter by status
            limit: Maximum number of deliveries
            
        Returns:
            List of deliveries
        """
        deliveries = list(self.deliveries.values())
        
        if webhook_id:
            deliveries = [d for d in deliveries if d.webhook_id == webhook_id]
        
        if status:
            deliveries = [d for d in deliveries if d.status == status]
        
        # Sort by created_at descending
        deliveries.sort(key=lambda d: d.created_at, reverse=True)
        
        return deliveries[:limit]
    
    def _load_webhooks(self):
        """Load webhooks from storage."""
        try:
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
                self.webhooks = {
                    wid: Webhook.from_dict(wdata)
                    for wid, wdata in data.get('webhooks', {}).items()
                }
        except FileNotFoundError:
            self.webhooks = {}
        except Exception as e:
            print(f"Error loading webhooks: {e}")
            self.webhooks = {}
    
    def _save_webhooks(self):
        """Save webhooks to storage."""
        try:
            data = {
                'webhooks': {
                    wid: webhook.to_dict()
                    for wid, webhook in self.webhooks.items()
                }
            }
            with open(self.storage_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving webhooks: {e}")

