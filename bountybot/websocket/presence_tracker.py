"""
User presence tracking and collaborative features.
"""

import asyncio
import logging
from typing import Dict, Set, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field

from bountybot.websocket.models import (
    UserPresence,
    PresenceStatus,
    MessageType,
    WebSocketMessage,
)
from bountybot.websocket.server import WebSocketServer


logger = logging.getLogger(__name__)


@dataclass
class TypingIndicator:
    """Typing indicator for a user in a specific context."""
    user_id: str
    user_name: str
    entity_type: str
    entity_id: str
    started_at: datetime = field(default_factory=datetime.utcnow)
    last_update: datetime = field(default_factory=datetime.utcnow)
    
    def is_expired(self, timeout_seconds: int = 5) -> bool:
        """Check if typing indicator has expired."""
        elapsed = (datetime.utcnow() - self.last_update).total_seconds()
        return elapsed > timeout_seconds
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'user_id': self.user_id,
            'user_name': self.user_name,
            'entity_type': self.entity_type,
            'entity_id': self.entity_id,
            'started_at': self.started_at.isoformat(),
            'last_update': self.last_update.isoformat(),
        }


class PresenceTracker:
    """
    Tracks user presence and collaborative features.
    """
    
    def __init__(self, websocket_server: Optional[WebSocketServer] = None,
                 away_timeout_minutes: int = 5):
        """
        Initialize presence tracker.
        
        Args:
            websocket_server: WebSocket server for broadcasting presence updates
            away_timeout_minutes: Minutes of inactivity before marking user as away
        """
        self.websocket_server = websocket_server
        self.away_timeout = timedelta(minutes=away_timeout_minutes)
        
        # User presence tracking
        self.user_presence: Dict[str, UserPresence] = {}
        
        # Typing indicators: entity_key -> {user_id -> TypingIndicator}
        self.typing_indicators: Dict[str, Dict[str, TypingIndicator]] = {}
        
        # Active users by room: room_id -> {user_id}
        self.room_users: Dict[str, Set[str]] = {}
        
        # Background task for cleanup
        self.cleanup_task: Optional[asyncio.Task] = None
        self.running = False
    
    def _get_entity_key(self, entity_type: str, entity_id: str) -> str:
        """Get entity key for typing indicators."""
        return f"{entity_type}:{entity_id}"
    
    async def start(self) -> None:
        """Start presence tracker background tasks."""
        if self.running:
            return
        
        self.running = True
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("Presence tracker started")
    
    async def stop(self) -> None:
        """Stop presence tracker background tasks."""
        if not self.running:
            return
        
        self.running = False
        
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Presence tracker stopped")
    
    async def _cleanup_loop(self) -> None:
        """Background loop to clean up expired typing indicators and update presence."""
        while self.running:
            try:
                await self._cleanup_typing_indicators()
                await self._update_away_status()
                await asyncio.sleep(5)  # Run every 5 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
    
    async def _cleanup_typing_indicators(self) -> None:
        """Remove expired typing indicators."""
        for entity_key, indicators in list(self.typing_indicators.items()):
            expired_users = [
                user_id for user_id, indicator in indicators.items()
                if indicator.is_expired()
            ]
            
            for user_id in expired_users:
                indicator = indicators[user_id]
                del indicators[user_id]
                
                # Broadcast typing stop
                if self.websocket_server:
                    room = entity_key
                    message = WebSocketMessage(
                        type=MessageType.TYPING_STOP,
                        data={
                            'user_id': user_id,
                            'entity_type': indicator.entity_type,
                            'entity_id': indicator.entity_id,
                        },
                        room=room,
                    )
                    await self.websocket_server.send_to_room(room, message)
            
            # Remove empty entity keys
            if not indicators:
                del self.typing_indicators[entity_key]
    
    async def _update_away_status(self) -> None:
        """Update users to away status if inactive."""
        now = datetime.utcnow()
        
        for user_id, presence in self.user_presence.items():
            if presence.status == PresenceStatus.ONLINE:
                elapsed = now - presence.last_seen
                if elapsed > self.away_timeout:
                    await self.update_presence(user_id, PresenceStatus.AWAY)
    
    async def update_presence(self, user_id: str, status: PresenceStatus,
                            user_name: Optional[str] = None,
                            current_room: Optional[str] = None,
                            metadata: Optional[Dict[str, Any]] = None) -> UserPresence:
        """
        Update user presence.
        
        Args:
            user_id: User ID
            status: Presence status
            user_name: User name (required for first update)
            current_room: Current room user is in
            metadata: Additional metadata
            
        Returns:
            Updated UserPresence object
        """
        if user_id in self.user_presence:
            presence = self.user_presence[user_id]
            presence.status = status
            presence.last_seen = datetime.utcnow()
            if current_room is not None:
                presence.current_room = current_room
            if metadata:
                presence.metadata.update(metadata)
        else:
            if not user_name:
                raise ValueError("user_name required for first presence update")
            
            presence = UserPresence(
                user_id=user_id,
                user_name=user_name,
                status=status,
                current_room=current_room,
                metadata=metadata or {},
            )
            self.user_presence[user_id] = presence
        
        # Broadcast presence update
        if self.websocket_server:
            message = WebSocketMessage(
                type=MessageType.PRESENCE_UPDATE,
                data=presence.to_dict(),
            )
            await self.websocket_server.send_to_user(user_id, message)
            
            # Also broadcast to current room
            if presence.current_room:
                await self.websocket_server.send_to_room(presence.current_room, message)
        
        logger.info(f"Presence updated: {user_id} -> {status.value}")
        return presence
    
    def get_presence(self, user_id: str) -> Optional[UserPresence]:
        """Get user presence."""
        return self.user_presence.get(user_id)
    
    def get_online_users(self) -> list[UserPresence]:
        """Get all online users."""
        return [
            p for p in self.user_presence.values()
            if p.status in (PresenceStatus.ONLINE, PresenceStatus.AWAY, PresenceStatus.BUSY)
        ]
    
    def get_room_users(self, room_id: str) -> Set[str]:
        """Get all users in a room."""
        return self.room_users.get(room_id, set())
    
    async def join_room(self, user_id: str, room_id: str) -> None:
        """Add user to room."""
        if room_id not in self.room_users:
            self.room_users[room_id] = set()
        
        self.room_users[room_id].add(user_id)
        
        # Update presence
        if user_id in self.user_presence:
            await self.update_presence(user_id, self.user_presence[user_id].status,
                                      current_room=room_id)
        
        logger.info(f"User {user_id} joined room {room_id}")
    
    async def leave_room(self, user_id: str, room_id: str) -> None:
        """Remove user from room."""
        if room_id in self.room_users:
            self.room_users[room_id].discard(user_id)
            
            if not self.room_users[room_id]:
                del self.room_users[room_id]
        
        # Update presence
        if user_id in self.user_presence:
            await self.update_presence(user_id, self.user_presence[user_id].status,
                                      current_room=None)
        
        logger.info(f"User {user_id} left room {room_id}")
    
    async def start_typing(self, user_id: str, user_name: str,
                          entity_type: str, entity_id: str) -> None:
        """
        Start typing indicator for user.
        
        Args:
            user_id: User ID
            user_name: User name
            entity_type: Entity type (report, workflow, etc.)
            entity_id: Entity ID
        """
        entity_key = self._get_entity_key(entity_type, entity_id)
        
        if entity_key not in self.typing_indicators:
            self.typing_indicators[entity_key] = {}
        
        if user_id in self.typing_indicators[entity_key]:
            # Update existing indicator
            self.typing_indicators[entity_key][user_id].last_update = datetime.utcnow()
        else:
            # Create new indicator
            indicator = TypingIndicator(
                user_id=user_id,
                user_name=user_name,
                entity_type=entity_type,
                entity_id=entity_id,
            )
            self.typing_indicators[entity_key][user_id] = indicator
            
            # Broadcast typing start
            if self.websocket_server:
                room = entity_key
                message = WebSocketMessage(
                    type=MessageType.TYPING_START,
                    data=indicator.to_dict(),
                    room=room,
                )
                await self.websocket_server.send_to_room(room, message)
            
            logger.info(f"Typing started: {user_id} in {entity_key}")
    
    async def stop_typing(self, user_id: str, entity_type: str, entity_id: str) -> None:
        """
        Stop typing indicator for user.
        
        Args:
            user_id: User ID
            entity_type: Entity type
            entity_id: Entity ID
        """
        entity_key = self._get_entity_key(entity_type, entity_id)
        
        if entity_key in self.typing_indicators and user_id in self.typing_indicators[entity_key]:
            indicator = self.typing_indicators[entity_key][user_id]
            del self.typing_indicators[entity_key][user_id]
            
            # Broadcast typing stop
            if self.websocket_server:
                room = entity_key
                message = WebSocketMessage(
                    type=MessageType.TYPING_STOP,
                    data={
                        'user_id': user_id,
                        'entity_type': entity_type,
                        'entity_id': entity_id,
                    },
                    room=room,
                )
                await self.websocket_server.send_to_room(room, message)
            
            logger.info(f"Typing stopped: {user_id} in {entity_key}")
            
            # Clean up empty entity key
            if not self.typing_indicators[entity_key]:
                del self.typing_indicators[entity_key]
    
    def get_typing_users(self, entity_type: str, entity_id: str) -> list[TypingIndicator]:
        """Get all users currently typing in an entity."""
        entity_key = self._get_entity_key(entity_type, entity_id)
        indicators = self.typing_indicators.get(entity_key, {})
        return list(indicators.values())
    
    def get_stats(self) -> Dict[str, Any]:
        """Get presence tracker statistics."""
        status_counts = {}
        for status in PresenceStatus:
            status_counts[status.value] = sum(
                1 for p in self.user_presence.values() if p.status == status
            )
        
        return {
            'total_users': len(self.user_presence),
            'online_users': len(self.get_online_users()),
            'status_counts': status_counts,
            'active_rooms': len(self.room_users),
            'typing_contexts': len(self.typing_indicators),
        }

