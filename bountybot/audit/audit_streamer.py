"""
Audit Streamer

Real-time audit log streaming via WebSocket.
"""

import asyncio
import json
from typing import Set, Callable, Optional, List
from datetime import datetime

from .models import AuditEvent, AuditEventType, AuditSeverity


class AuditSubscription:
    """Audit event subscription."""
    
    def __init__(
        self,
        subscription_id: str,
        callback: Callable,
        event_types: Optional[List[AuditEventType]] = None,
        severities: Optional[List[AuditSeverity]] = None,
        user_ids: Optional[List[str]] = None,
        org_ids: Optional[List[str]] = None
    ):
        self.subscription_id = subscription_id
        self.callback = callback
        self.event_types = event_types or []
        self.severities = severities or []
        self.user_ids = user_ids or []
        self.org_ids = org_ids or []
        self.created_at = datetime.utcnow()
        self.event_count = 0
    
    def matches(self, event: AuditEvent) -> bool:
        """Check if event matches subscription filters."""
        
        # Check event type filter
        if self.event_types and event.event_type not in self.event_types:
            return False
        
        # Check severity filter
        if self.severities and event.severity not in self.severities:
            return False
        
        # Check user filter
        if self.user_ids and event.user_id not in self.user_ids:
            return False
        
        # Check org filter
        if self.org_ids and event.org_id not in self.org_ids:
            return False
        
        return True


class AuditStreamer:
    """
    Real-time audit log streaming.
    
    Features:
    - WebSocket-based streaming
    - Filtered subscriptions
    - Broadcast to multiple subscribers
    - Async event delivery
    """
    
    def __init__(self):
        self.subscriptions: dict[str, AuditSubscription] = {}
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self.running = False
    
    def subscribe(
        self,
        subscription_id: str,
        callback: Callable,
        event_types: Optional[List[AuditEventType]] = None,
        severities: Optional[List[AuditSeverity]] = None,
        user_ids: Optional[List[str]] = None,
        org_ids: Optional[List[str]] = None
    ) -> AuditSubscription:
        """Subscribe to audit events."""
        
        subscription = AuditSubscription(
            subscription_id=subscription_id,
            callback=callback,
            event_types=event_types,
            severities=severities,
            user_ids=user_ids,
            org_ids=org_ids
        )
        
        self.subscriptions[subscription_id] = subscription
        return subscription
    
    def unsubscribe(self, subscription_id: str) -> bool:
        """Unsubscribe from audit events."""
        if subscription_id in self.subscriptions:
            del self.subscriptions[subscription_id]
            return True
        return False
    
    async def publish(self, event: AuditEvent):
        """Publish event to subscribers."""
        await self.event_queue.put(event)
    
    async def start(self):
        """Start the streamer."""
        self.running = True
        
        while self.running:
            try:
                # Get event from queue
                event = await asyncio.wait_for(
                    self.event_queue.get(),
                    timeout=1.0
                )
                
                # Broadcast to matching subscribers
                await self._broadcast_event(event)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                print(f"Error in audit streamer: {e}")
    
    async def stop(self):
        """Stop the streamer."""
        self.running = False
    
    async def _broadcast_event(self, event: AuditEvent):
        """Broadcast event to all matching subscribers."""
        
        tasks = []
        
        for subscription in self.subscriptions.values():
            if subscription.matches(event):
                # Create task for async callback
                task = asyncio.create_task(
                    self._deliver_event(subscription, event)
                )
                tasks.append(task)
        
        # Wait for all deliveries
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _deliver_event(
        self,
        subscription: AuditSubscription,
        event: AuditEvent
    ):
        """Deliver event to subscriber."""
        try:
            # Call the callback
            if asyncio.iscoroutinefunction(subscription.callback):
                await subscription.callback(event)
            else:
                subscription.callback(event)
            
            subscription.event_count += 1
            
        except Exception as e:
            print(f"Error delivering event to {subscription.subscription_id}: {e}")
    
    def get_subscription_stats(self) -> dict:
        """Get subscription statistics."""
        return {
            'total_subscriptions': len(self.subscriptions),
            'subscriptions': [
                {
                    'subscription_id': sub.subscription_id,
                    'created_at': sub.created_at.isoformat(),
                    'event_count': sub.event_count,
                    'filters': {
                        'event_types': [et.value for et in sub.event_types],
                        'severities': [s.value for s in sub.severities],
                        'user_ids': sub.user_ids,
                        'org_ids': sub.org_ids
                    }
                }
                for sub in self.subscriptions.values()
            ]
        }


class AuditWebSocketHandler:
    """WebSocket handler for audit streaming."""
    
    def __init__(self, streamer: AuditStreamer):
        self.streamer = streamer
        self.connections: Set[any] = set()
    
    async def handle_connection(self, websocket):
        """Handle WebSocket connection."""
        self.connections.add(websocket)
        
        try:
            # Create subscription for this connection
            subscription_id = f"ws_{id(websocket)}"
            
            async def send_to_websocket(event: AuditEvent):
                """Send event to WebSocket."""
                try:
                    await websocket.send(json.dumps(event.to_dict()))
                except Exception:
                    pass
            
            subscription = self.streamer.subscribe(
                subscription_id=subscription_id,
                callback=send_to_websocket
            )
            
            # Keep connection alive
            async for message in websocket:
                # Handle incoming messages (e.g., filter updates)
                try:
                    data = json.loads(message)
                    
                    if data.get('action') == 'update_filters':
                        # Update subscription filters
                        filters = data.get('filters', {})
                        
                        if 'event_types' in filters:
                            subscription.event_types = [
                                AuditEventType(et) for et in filters['event_types']
                            ]
                        
                        if 'severities' in filters:
                            subscription.severities = [
                                AuditSeverity(s) for s in filters['severities']
                            ]
                
                except json.JSONDecodeError:
                    pass
        
        finally:
            # Clean up
            self.connections.remove(websocket)
            self.streamer.unsubscribe(subscription_id)
    
    async def broadcast(self, message: str):
        """Broadcast message to all connections."""
        if self.connections:
            await asyncio.gather(
                *[ws.send(message) for ws in self.connections],
                return_exceptions=True
            )

