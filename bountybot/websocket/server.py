"""
WebSocket server implementation with connection management.
"""

import asyncio
import json
import logging
from typing import Dict, Set, Optional, Any, Callable, List
from datetime import datetime
import websockets
from websockets.server import WebSocketServerProtocol

from bountybot.websocket.models import (
    WebSocketMessage,
    MessageType,
    EventType,
    ConnectionStatus,
    Connection,
    Subscription,
    Room,
)


logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Manages WebSocket connections, subscriptions, and rooms.
    """
    
    def __init__(self):
        """Initialize connection manager."""
        self.connections: Dict[str, Connection] = {}
        self.websockets: Dict[str, WebSocketServerProtocol] = {}
        self.rooms: Dict[str, Room] = {}
        self.user_connections: Dict[str, Set[str]] = {}  # user_id -> connection_ids
        
    def add_connection(self, connection_id: str, websocket: WebSocketServerProtocol,
                      user_id: Optional[str] = None) -> Connection:
        """Add new connection."""
        connection = Connection(
            connection_id=connection_id,
            user_id=user_id,
            status=ConnectionStatus.CONNECTED,
        )
        
        self.connections[connection_id] = connection
        self.websockets[connection_id] = websocket
        
        if user_id:
            if user_id not in self.user_connections:
                self.user_connections[user_id] = set()
            self.user_connections[user_id].add(connection_id)
        
        logger.info(f"Connection added: {connection_id} (user: {user_id})")
        return connection
    
    def remove_connection(self, connection_id: str) -> None:
        """Remove connection."""
        if connection_id in self.connections:
            connection = self.connections[connection_id]
            
            # Remove from user connections
            if connection.user_id and connection.user_id in self.user_connections:
                self.user_connections[connection.user_id].discard(connection_id)
                if not self.user_connections[connection.user_id]:
                    del self.user_connections[connection.user_id]
            
            # Remove from rooms
            for room in self.rooms.values():
                if connection.user_id:
                    room.remove_member(connection.user_id)
            
            del self.connections[connection_id]
            del self.websockets[connection_id]
            
            logger.info(f"Connection removed: {connection_id}")
    
    def get_connection(self, connection_id: str) -> Optional[Connection]:
        """Get connection by ID."""
        return self.connections.get(connection_id)
    
    def get_websocket(self, connection_id: str) -> Optional[WebSocketServerProtocol]:
        """Get websocket by connection ID."""
        return self.websockets.get(connection_id)
    
    def get_user_connections(self, user_id: str) -> List[str]:
        """Get all connection IDs for a user."""
        return list(self.user_connections.get(user_id, set()))
    
    def add_subscription(self, connection_id: str, subscription: Subscription) -> bool:
        """Add subscription to connection."""
        connection = self.get_connection(connection_id)
        if not connection:
            return False
        
        connection.subscriptions.append(subscription)
        logger.info(f"Subscription added to {connection_id}: {subscription.subscription_id}")
        return True
    
    def remove_subscription(self, connection_id: str, subscription_id: str) -> bool:
        """Remove subscription from connection."""
        connection = self.get_connection(connection_id)
        if not connection:
            return False
        
        connection.subscriptions = [
            s for s in connection.subscriptions 
            if s.subscription_id != subscription_id
        ]
        logger.info(f"Subscription removed from {connection_id}: {subscription_id}")
        return True
    
    def create_room(self, room_id: str, name: str, description: Optional[str] = None) -> Room:
        """Create a new room."""
        room = Room(
            room_id=room_id,
            name=name,
            description=description,
        )
        self.rooms[room_id] = room
        logger.info(f"Room created: {room_id}")
        return room
    
    def get_room(self, room_id: str) -> Optional[Room]:
        """Get room by ID."""
        return self.rooms.get(room_id)
    
    def join_room(self, connection_id: str, room_id: str) -> bool:
        """Add connection to room."""
        connection = self.get_connection(connection_id)
        room = self.get_room(room_id)
        
        if not connection or not room or not connection.user_id:
            return False
        
        room.add_member(connection.user_id)
        logger.info(f"User {connection.user_id} joined room {room_id}")
        return True
    
    def leave_room(self, connection_id: str, room_id: str) -> bool:
        """Remove connection from room."""
        connection = self.get_connection(connection_id)
        room = self.get_room(room_id)
        
        if not connection or not room or not connection.user_id:
            return False
        
        room.remove_member(connection.user_id)
        logger.info(f"User {connection.user_id} left room {room_id}")
        return True
    
    def get_room_members(self, room_id: str) -> Set[str]:
        """Get all user IDs in a room."""
        room = self.get_room(room_id)
        return room.members if room else set()
    
    def find_matching_connections(self, event_type: EventType, room: Optional[str] = None,
                                 event_data: Optional[Dict[str, Any]] = None) -> List[str]:
        """Find all connections that should receive an event."""
        matching_connections = []
        
        for connection_id, connection in self.connections.items():
            for subscription in connection.subscriptions:
                if subscription.matches_event(event_type, room, event_data):
                    matching_connections.append(connection_id)
                    break  # Only add connection once
        
        return matching_connections
    
    def update_ping(self, connection_id: str) -> None:
        """Update last ping time for connection."""
        connection = self.get_connection(connection_id)
        if connection:
            connection.last_ping = datetime.utcnow()
    
    def update_pong(self, connection_id: str) -> None:
        """Update last pong time for connection."""
        connection = self.get_connection(connection_id)
        if connection:
            connection.last_pong = datetime.utcnow()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connection statistics."""
        return {
            'total_connections': len(self.connections),
            'total_users': len(self.user_connections),
            'total_rooms': len(self.rooms),
            'connections_by_status': {
                status.value: sum(1 for c in self.connections.values() if c.status == status)
                for status in ConnectionStatus
            },
        }


class WebSocketServer:
    """
    WebSocket server for real-time communication.
    """
    
    def __init__(self, host: str = "localhost", port: int = 8765,
                 auth_callback: Optional[Callable] = None):
        """
        Initialize WebSocket server.
        
        Args:
            host: Server host
            port: Server port
            auth_callback: Optional authentication callback function
        """
        self.host = host
        self.port = port
        self.auth_callback = auth_callback
        self.connection_manager = ConnectionManager()
        self.message_handlers: Dict[MessageType, Callable] = {}
        self.running = False
        self.server = None
        
        # Register default handlers
        self._register_default_handlers()
    
    def _register_default_handlers(self) -> None:
        """Register default message handlers."""
        self.register_handler(MessageType.PING, self._handle_ping)
        self.register_handler(MessageType.SUBSCRIBE, self._handle_subscribe)
        self.register_handler(MessageType.UNSUBSCRIBE, self._handle_unsubscribe)
    
    def register_handler(self, message_type: MessageType, handler: Callable) -> None:
        """Register message handler."""
        self.message_handlers[message_type] = handler
        logger.info(f"Handler registered for {message_type.value}")
    
    async def _handle_ping(self, connection_id: str, message: WebSocketMessage) -> None:
        """Handle ping message."""
        self.connection_manager.update_pong(connection_id)
        
        # Send pong response
        pong_message = WebSocketMessage(
            type=MessageType.PONG,
            data={'timestamp': datetime.utcnow().isoformat()},
        )
        await self.send_message(connection_id, pong_message)
    
    async def _handle_subscribe(self, connection_id: str, message: WebSocketMessage) -> None:
        """Handle subscription request."""
        event_types = [EventType(et) for et in message.data.get('event_types', [])]
        rooms = set(message.data.get('rooms', []))
        filters = message.data.get('filters', {})
        
        subscription = Subscription(
            user_id=message.user_id or "",
            event_types=set(event_types),
            rooms=rooms,
            filters=filters,
        )
        
        success = self.connection_manager.add_subscription(connection_id, subscription)
        
        # Send acknowledgment
        ack_message = WebSocketMessage(
            type=MessageType.ACK,
            data={
                'success': success,
                'subscription_id': subscription.subscription_id,
            },
        )
        await self.send_message(connection_id, ack_message)
    
    async def _handle_unsubscribe(self, connection_id: str, message: WebSocketMessage) -> None:
        """Handle unsubscription request."""
        subscription_id = message.data.get('subscription_id')
        success = self.connection_manager.remove_subscription(connection_id, subscription_id)

        # Send acknowledgment
        ack_message = WebSocketMessage(
            type=MessageType.ACK,
            data={'success': success},
        )
        await self.send_message(connection_id, ack_message)

    async def handle_connection(self, websocket: WebSocketServerProtocol, path: str) -> None:
        """Handle new WebSocket connection."""
        connection_id = str(id(websocket))
        user_id = None

        try:
            # Authenticate if callback provided
            if self.auth_callback:
                user_id = await self.auth_callback(websocket, path)
                if not user_id:
                    await websocket.close(code=1008, reason="Authentication failed")
                    return

            # Add connection
            connection = self.connection_manager.add_connection(connection_id, websocket, user_id)

            # Send connection confirmation
            connect_message = WebSocketMessage(
                type=MessageType.CONNECT,
                data={
                    'connection_id': connection_id,
                    'user_id': user_id,
                    'timestamp': datetime.utcnow().isoformat(),
                },
            )
            await self.send_message(connection_id, connect_message)

            # Handle messages
            async for raw_message in websocket:
                try:
                    data = json.loads(raw_message)
                    message = WebSocketMessage.from_dict(data)
                    message.user_id = user_id  # Ensure user_id is set

                    # Route to handler
                    handler = self.message_handlers.get(message.type)
                    if handler:
                        await handler(connection_id, message)
                    else:
                        logger.warning(f"No handler for message type: {message.type.value}")

                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON from {connection_id}: {e}")
                    error_message = WebSocketMessage(
                        type=MessageType.ERROR,
                        data={'error': 'Invalid JSON'},
                    )
                    await self.send_message(connection_id, error_message)

                except Exception as e:
                    logger.error(f"Error handling message from {connection_id}: {e}")
                    error_message = WebSocketMessage(
                        type=MessageType.ERROR,
                        data={'error': str(e)},
                    )
                    await self.send_message(connection_id, error_message)

        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Connection closed: {connection_id}")

        except Exception as e:
            logger.error(f"Error in connection {connection_id}: {e}")

        finally:
            # Clean up connection
            self.connection_manager.remove_connection(connection_id)

    async def send_message(self, connection_id: str, message: WebSocketMessage) -> bool:
        """Send message to specific connection."""
        websocket = self.connection_manager.get_websocket(connection_id)
        if not websocket:
            return False

        try:
            await websocket.send(json.dumps(message.to_dict()))
            return True
        except Exception as e:
            logger.error(f"Error sending message to {connection_id}: {e}")
            return False

    async def broadcast_event(self, event_type: EventType, data: Dict[str, Any],
                            room: Optional[str] = None) -> int:
        """
        Broadcast event to all matching subscriptions.

        Returns:
            Number of connections that received the event
        """
        # Find matching connections
        matching_connections = self.connection_manager.find_matching_connections(
            event_type, room, data
        )

        # Create event message
        event_message = WebSocketMessage(
            type=MessageType.EVENT,
            event_type=event_type,
            data=data,
            room=room,
        )

        # Send to all matching connections
        sent_count = 0
        for connection_id in matching_connections:
            if await self.send_message(connection_id, event_message):
                sent_count += 1

        logger.info(f"Broadcast {event_type.value} to {sent_count} connections")
        return sent_count

    async def send_to_user(self, user_id: str, message: WebSocketMessage) -> int:
        """
        Send message to all connections of a user.

        Returns:
            Number of connections that received the message
        """
        connection_ids = self.connection_manager.get_user_connections(user_id)

        sent_count = 0
        for connection_id in connection_ids:
            if await self.send_message(connection_id, message):
                sent_count += 1

        return sent_count

    async def send_to_room(self, room_id: str, message: WebSocketMessage) -> int:
        """
        Send message to all members of a room.

        Returns:
            Number of users that received the message
        """
        members = self.connection_manager.get_room_members(room_id)

        sent_count = 0
        for user_id in members:
            sent_count += await self.send_to_user(user_id, message)

        return sent_count

    async def start(self) -> None:
        """Start WebSocket server."""
        if self.running:
            logger.warning("Server already running")
            return

        self.running = True
        self.server = await websockets.serve(
            self.handle_connection,
            self.host,
            self.port,
        )

        logger.info(f"WebSocket server started on ws://{self.host}:{self.port}")

    async def stop(self) -> None:
        """Stop WebSocket server."""
        if not self.running:
            return

        self.running = False

        if self.server:
            self.server.close()
            await self.server.wait_closed()

        logger.info("WebSocket server stopped")

    def get_stats(self) -> Dict[str, Any]:
        """Get server statistics."""
        return {
            'running': self.running,
            'host': self.host,
            'port': self.port,
            **self.connection_manager.get_stats(),
        }

