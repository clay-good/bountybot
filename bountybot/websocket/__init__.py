"""
Real-time WebSocket infrastructure for BountyBot.

This module provides real-time communication capabilities including:
- WebSocket server with connection management
- Event streaming for validation progress, workflows, and collaboration
- User presence tracking and collaborative features
- Live dashboard updates
"""

from bountybot.websocket.models import (
    WebSocketMessage,
    MessageType,
    EventType,
    ConnectionStatus,
    UserPresence,
    PresenceStatus,
    Room,
    Subscription,
)

from bountybot.websocket.server import (
    WebSocketServer,
    ConnectionManager,
)

from bountybot.websocket.event_emitter import (
    EventEmitter,
    ValidationEventEmitter,
    WorkflowEventEmitter,
    CollaborationEventEmitter,
    SystemEventEmitter,
)

from bountybot.websocket.presence_tracker import (
    PresenceTracker,
    TypingIndicator,
)

__all__ = [
    # Models
    'WebSocketMessage',
    'MessageType',
    'EventType',
    'ConnectionStatus',
    'UserPresence',
    'PresenceStatus',
    'Room',
    'Subscription',
    
    # Server
    'WebSocketServer',
    'ConnectionManager',
    
    # Event Emitters
    'EventEmitter',
    'ValidationEventEmitter',
    'WorkflowEventEmitter',
    'CollaborationEventEmitter',
    'SystemEventEmitter',
    
    # Presence
    'PresenceTracker',
    'TypingIndicator',
]

