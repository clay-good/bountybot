"""
Data models for WebSocket infrastructure.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Any, List, Optional, Set
from uuid import uuid4


class MessageType(Enum):
    """WebSocket message types."""
    # Connection management
    CONNECT = "connect"
    DISCONNECT = "disconnect"
    PING = "ping"
    PONG = "pong"
    
    # Subscription management
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    
    # Events
    EVENT = "event"
    
    # Presence
    PRESENCE_UPDATE = "presence_update"
    TYPING_START = "typing_start"
    TYPING_STOP = "typing_stop"
    
    # Errors
    ERROR = "error"
    
    # Acknowledgments
    ACK = "ack"


class EventType(Enum):
    """Event types for real-time streaming."""
    # Validation events
    VALIDATION_STARTED = "validation.started"
    VALIDATION_PROGRESS = "validation.progress"
    VALIDATION_COMPLETED = "validation.completed"
    VALIDATION_FAILED = "validation.failed"
    
    # Workflow events
    WORKFLOW_CREATED = "workflow.created"
    WORKFLOW_UPDATED = "workflow.updated"
    WORKFLOW_STATE_CHANGED = "workflow.state_changed"
    WORKFLOW_TASK_ASSIGNED = "workflow.task_assigned"
    WORKFLOW_TASK_COMPLETED = "workflow.task_completed"
    
    # Collaboration events
    COMMENT_ADDED = "collaboration.comment_added"
    COMMENT_UPDATED = "collaboration.comment_updated"
    COMMENT_DELETED = "collaboration.comment_deleted"
    MENTION_CREATED = "collaboration.mention_created"
    REACTION_ADDED = "collaboration.reaction_added"
    
    # SLA events
    SLA_CREATED = "sla.created"
    SLA_WARNING = "sla.warning"
    SLA_BREACHED = "sla.breached"
    SLA_COMPLETED = "sla.completed"
    
    # Escalation events
    ESCALATION_TRIGGERED = "escalation.triggered"
    ESCALATION_RESOLVED = "escalation.resolved"
    
    # System events
    SYSTEM_HEALTH_UPDATE = "system.health_update"
    SYSTEM_METRICS_UPDATE = "system.metrics_update"
    SYSTEM_ALERT = "system.alert"


class ConnectionStatus(Enum):
    """WebSocket connection status."""
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    DISCONNECTED = "disconnected"
    RECONNECTING = "reconnecting"
    ERROR = "error"


class PresenceStatus(Enum):
    """User presence status."""
    ONLINE = "online"
    AWAY = "away"
    BUSY = "busy"
    OFFLINE = "offline"


@dataclass
class WebSocketMessage:
    """WebSocket message structure."""
    type: MessageType
    data: Dict[str, Any] = field(default_factory=dict)
    event_type: Optional[EventType] = None
    message_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    user_id: Optional[str] = None
    room: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary for JSON serialization."""
        return {
            'type': self.type.value,
            'data': self.data,
            'event_type': self.event_type.value if self.event_type else None,
            'message_id': self.message_id,
            'timestamp': self.timestamp.isoformat(),
            'user_id': self.user_id,
            'room': self.room,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WebSocketMessage':
        """Create message from dictionary."""
        return cls(
            type=MessageType(data['type']),
            data=data.get('data', {}),
            event_type=EventType(data['event_type']) if data.get('event_type') else None,
            message_id=data.get('message_id', str(uuid4())),
            timestamp=datetime.fromisoformat(data['timestamp']) if data.get('timestamp') else datetime.utcnow(),
            user_id=data.get('user_id'),
            room=data.get('room'),
        )


@dataclass
class UserPresence:
    """User presence information."""
    user_id: str
    user_name: str
    status: PresenceStatus
    last_seen: datetime = field(default_factory=datetime.utcnow)
    current_room: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'user_id': self.user_id,
            'user_name': self.user_name,
            'status': self.status.value,
            'last_seen': self.last_seen.isoformat(),
            'current_room': self.current_room,
            'metadata': self.metadata,
        }


@dataclass
class Room:
    """WebSocket room for grouped subscriptions."""
    room_id: str
    name: str
    description: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    members: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_member(self, user_id: str) -> None:
        """Add member to room."""
        self.members.add(user_id)
    
    def remove_member(self, user_id: str) -> None:
        """Remove member from room."""
        self.members.discard(user_id)
    
    def has_member(self, user_id: str) -> bool:
        """Check if user is member of room."""
        return user_id in self.members
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'room_id': self.room_id,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at.isoformat(),
            'members': list(self.members),
            'member_count': len(self.members),
            'metadata': self.metadata,
        }


@dataclass
class Subscription:
    """User subscription to events."""
    subscription_id: str = field(default_factory=lambda: str(uuid4()))
    user_id: str = ""
    event_types: Set[EventType] = field(default_factory=set)
    rooms: Set[str] = field(default_factory=set)
    filters: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def matches_event(self, event_type: EventType, room: Optional[str] = None,
                     event_data: Optional[Dict[str, Any]] = None) -> bool:
        """Check if subscription matches event."""
        # Check event type
        if self.event_types and event_type not in self.event_types:
            return False

        # Check room
        if self.rooms and (not room or room not in self.rooms):
            return False

        # Check filters
        if self.filters and event_data:
            for key, value in self.filters.items():
                if event_data.get(key) != value:
                    return False

        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'subscription_id': self.subscription_id,
            'user_id': self.user_id,
            'event_types': [et.value for et in self.event_types],
            'rooms': list(self.rooms),
            'filters': self.filters,
            'created_at': self.created_at.isoformat(),
        }


@dataclass
class Connection:
    """WebSocket connection information."""
    connection_id: str = field(default_factory=lambda: str(uuid4()))
    user_id: Optional[str] = None
    status: ConnectionStatus = ConnectionStatus.CONNECTING
    connected_at: datetime = field(default_factory=datetime.utcnow)
    last_ping: Optional[datetime] = None
    last_pong: Optional[datetime] = None
    subscriptions: List[Subscription] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_alive(self, timeout_seconds: int = 60) -> bool:
        """Check if connection is alive based on ping/pong."""
        if not self.last_ping:
            return True  # No ping sent yet
        
        if not self.last_pong:
            # Check if ping timeout exceeded
            elapsed = (datetime.utcnow() - self.last_ping).total_seconds()
            return elapsed < timeout_seconds
        
        # Check if pong is recent enough
        elapsed = (datetime.utcnow() - self.last_pong).total_seconds()
        return elapsed < timeout_seconds
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'connection_id': self.connection_id,
            'user_id': self.user_id,
            'status': self.status.value,
            'connected_at': self.connected_at.isoformat(),
            'last_ping': self.last_ping.isoformat() if self.last_ping else None,
            'last_pong': self.last_pong.isoformat() if self.last_pong else None,
            'subscriptions': [s.to_dict() for s in self.subscriptions],
            'metadata': self.metadata,
        }

