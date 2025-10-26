"""
Tests for WebSocket infrastructure.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch

from bountybot.websocket.models import (
    WebSocketMessage,
    MessageType,
    EventType,
    ConnectionStatus,
    UserPresence,
    PresenceStatus,
    Room,
    Subscription,
    Connection,
)
from bountybot.websocket.server import (
    ConnectionManager,
    WebSocketServer,
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


class TestWebSocketMessage:
    """Test WebSocket message models."""
    
    def test_message_creation(self):
        """Test creating a WebSocket message."""
        message = WebSocketMessage(
            type=MessageType.EVENT,
            event_type=EventType.VALIDATION_STARTED,
            data={'validation_id': 'test-123'},
            user_id='user-1',
        )
        
        assert message.type == MessageType.EVENT
        assert message.event_type == EventType.VALIDATION_STARTED
        assert message.data['validation_id'] == 'test-123'
        assert message.user_id == 'user-1'
        assert message.message_id is not None
    
    def test_message_to_dict(self):
        """Test converting message to dictionary."""
        message = WebSocketMessage(
            type=MessageType.PING,
            data={'timestamp': '2025-10-18T10:00:00'},
        )
        
        data = message.to_dict()
        
        assert data['type'] == 'ping'
        assert data['data']['timestamp'] == '2025-10-18T10:00:00'
        assert 'message_id' in data
        assert 'timestamp' in data
    
    def test_message_from_dict(self):
        """Test creating message from dictionary."""
        data = {
            'type': 'event',
            'event_type': 'validation.started',
            'data': {'validation_id': 'test-123'},
            'message_id': 'msg-1',
            'timestamp': '2025-10-18T10:00:00',
            'user_id': 'user-1',
        }
        
        message = WebSocketMessage.from_dict(data)
        
        assert message.type == MessageType.EVENT
        assert message.event_type == EventType.VALIDATION_STARTED
        assert message.data['validation_id'] == 'test-123'
        assert message.user_id == 'user-1'


class TestUserPresence:
    """Test user presence models."""
    
    def test_presence_creation(self):
        """Test creating user presence."""
        presence = UserPresence(
            user_id='user-1',
            user_name='Alice',
            status=PresenceStatus.ONLINE,
        )
        
        assert presence.user_id == 'user-1'
        assert presence.user_name == 'Alice'
        assert presence.status == PresenceStatus.ONLINE
        assert presence.last_seen is not None
    
    def test_presence_to_dict(self):
        """Test converting presence to dictionary."""
        presence = UserPresence(
            user_id='user-1',
            user_name='Alice',
            status=PresenceStatus.ONLINE,
            current_room='room-1',
        )
        
        data = presence.to_dict()
        
        assert data['user_id'] == 'user-1'
        assert data['user_name'] == 'Alice'
        assert data['status'] == 'online'
        assert data['current_room'] == 'room-1'


class TestRoom:
    """Test room models."""
    
    def test_room_creation(self):
        """Test creating a room."""
        room = Room(
            room_id='room-1',
            name='Validation Room',
            description='Room for validation events',
        )
        
        assert room.room_id == 'room-1'
        assert room.name == 'Validation Room'
        assert len(room.members) == 0
    
    def test_add_member(self):
        """Test adding member to room."""
        room = Room(room_id='room-1', name='Test Room')
        
        room.add_member('user-1')
        room.add_member('user-2')
        
        assert len(room.members) == 2
        assert 'user-1' in room.members
        assert 'user-2' in room.members
    
    def test_remove_member(self):
        """Test removing member from room."""
        room = Room(room_id='room-1', name='Test Room')
        room.add_member('user-1')
        room.add_member('user-2')
        
        room.remove_member('user-1')
        
        assert len(room.members) == 1
        assert 'user-1' not in room.members
        assert 'user-2' in room.members
    
    def test_has_member(self):
        """Test checking room membership."""
        room = Room(room_id='room-1', name='Test Room')
        room.add_member('user-1')
        
        assert room.has_member('user-1')
        assert not room.has_member('user-2')


class TestSubscription:
    """Test subscription models."""
    
    def test_subscription_creation(self):
        """Test creating a subscription."""
        subscription = Subscription(
            user_id='user-1',
            event_types={EventType.VALIDATION_STARTED, EventType.VALIDATION_COMPLETED},
            rooms={'room-1'},
        )
        
        assert subscription.user_id == 'user-1'
        assert len(subscription.event_types) == 2
        assert 'room-1' in subscription.rooms
    
    def test_matches_event_type(self):
        """Test subscription matching by event type."""
        subscription = Subscription(
            user_id='user-1',
            event_types={EventType.VALIDATION_STARTED},
        )
        
        assert subscription.matches_event(EventType.VALIDATION_STARTED)
        assert not subscription.matches_event(EventType.VALIDATION_COMPLETED)
    
    def test_matches_room(self):
        """Test subscription matching by room."""
        subscription = Subscription(
            user_id='user-1',
            event_types={EventType.VALIDATION_STARTED},
            rooms={'room-1'},
        )
        
        assert subscription.matches_event(EventType.VALIDATION_STARTED, room='room-1')
        assert not subscription.matches_event(EventType.VALIDATION_STARTED, room='room-2')
    
    def test_matches_filters(self):
        """Test subscription matching by filters."""
        subscription = Subscription(
            user_id='user-1',
            event_types={EventType.VALIDATION_STARTED},
            filters={'severity': 'high'},
        )
        
        assert subscription.matches_event(
            EventType.VALIDATION_STARTED,
            event_data={'severity': 'high'}
        )
        assert not subscription.matches_event(
            EventType.VALIDATION_STARTED,
            event_data={'severity': 'low'}
        )


class TestConnection:
    """Test connection models."""
    
    def test_connection_creation(self):
        """Test creating a connection."""
        connection = Connection(
            user_id='user-1',
            status=ConnectionStatus.CONNECTED,
        )
        
        assert connection.user_id == 'user-1'
        assert connection.status == ConnectionStatus.CONNECTED
        assert connection.connection_id is not None
    
    def test_is_alive_no_ping(self):
        """Test connection alive check with no ping."""
        connection = Connection()
        
        assert connection.is_alive()
    
    def test_is_alive_with_recent_pong(self):
        """Test connection alive check with recent pong."""
        connection = Connection()
        connection.last_ping = datetime.utcnow() - timedelta(seconds=30)
        connection.last_pong = datetime.utcnow() - timedelta(seconds=10)
        
        assert connection.is_alive(timeout_seconds=60)
    
    def test_is_alive_timeout(self):
        """Test connection alive check with timeout."""
        connection = Connection()
        connection.last_ping = datetime.utcnow() - timedelta(seconds=70)
        connection.last_pong = datetime.utcnow() - timedelta(seconds=70)
        
        assert not connection.is_alive(timeout_seconds=60)


class TestConnectionManager:
    """Test connection manager."""
    
    def test_add_connection(self):
        """Test adding a connection."""
        manager = ConnectionManager()
        websocket = Mock()
        
        connection = manager.add_connection('conn-1', websocket, 'user-1')
        
        assert connection.connection_id == 'conn-1'
        assert connection.user_id == 'user-1'
        assert manager.get_connection('conn-1') == connection
        assert manager.get_websocket('conn-1') == websocket
    
    def test_remove_connection(self):
        """Test removing a connection."""
        manager = ConnectionManager()
        websocket = Mock()
        
        manager.add_connection('conn-1', websocket, 'user-1')
        manager.remove_connection('conn-1')
        
        assert manager.get_connection('conn-1') is None
        assert manager.get_websocket('conn-1') is None
    
    def test_get_user_connections(self):
        """Test getting user connections."""
        manager = ConnectionManager()
        ws1, ws2 = Mock(), Mock()
        
        manager.add_connection('conn-1', ws1, 'user-1')
        manager.add_connection('conn-2', ws2, 'user-1')
        
        connections = manager.get_user_connections('user-1')
        
        assert len(connections) == 2
        assert 'conn-1' in connections
        assert 'conn-2' in connections
    
    def test_add_subscription(self):
        """Test adding subscription to connection."""
        manager = ConnectionManager()
        websocket = Mock()
        
        manager.add_connection('conn-1', websocket, 'user-1')
        
        subscription = Subscription(
            user_id='user-1',
            event_types={EventType.VALIDATION_STARTED},
        )
        
        success = manager.add_subscription('conn-1', subscription)
        
        assert success
        connection = manager.get_connection('conn-1')
        assert len(connection.subscriptions) == 1
    
    def test_create_room(self):
        """Test creating a room."""
        manager = ConnectionManager()
        
        room = manager.create_room('room-1', 'Test Room', 'Description')
        
        assert room.room_id == 'room-1'
        assert room.name == 'Test Room'
        assert manager.get_room('room-1') == room
    
    def test_join_room(self):
        """Test joining a room."""
        manager = ConnectionManager()
        websocket = Mock()
        
        manager.add_connection('conn-1', websocket, 'user-1')
        manager.create_room('room-1', 'Test Room')
        
        success = manager.join_room('conn-1', 'room-1')
        
        assert success
        room = manager.get_room('room-1')
        assert 'user-1' in room.members
    
    def test_find_matching_connections(self):
        """Test finding connections matching event."""
        manager = ConnectionManager()
        ws1, ws2 = Mock(), Mock()
        
        manager.add_connection('conn-1', ws1, 'user-1')
        manager.add_connection('conn-2', ws2, 'user-2')
        
        # Add subscriptions
        sub1 = Subscription(
            user_id='user-1',
            event_types={EventType.VALIDATION_STARTED},
        )
        sub2 = Subscription(
            user_id='user-2',
            event_types={EventType.VALIDATION_COMPLETED},
        )
        
        manager.add_subscription('conn-1', sub1)
        manager.add_subscription('conn-2', sub2)
        
        # Find matching connections
        matches = manager.find_matching_connections(EventType.VALIDATION_STARTED)
        
        assert len(matches) == 1
        assert 'conn-1' in matches
    
    def test_get_stats(self):
        """Test getting connection statistics."""
        manager = ConnectionManager()
        ws1, ws2 = Mock(), Mock()
        
        manager.add_connection('conn-1', ws1, 'user-1')
        manager.add_connection('conn-2', ws2, 'user-2')
        manager.create_room('room-1', 'Test Room')
        
        stats = manager.get_stats()
        
        assert stats['total_connections'] == 2
        assert stats['total_users'] == 2
        assert stats['total_rooms'] == 1


class TestEventEmitter:
    """Test event emitters."""

    @pytest.mark.asyncio
    async def test_emit_without_server(self):
        """Test emitting event without WebSocket server."""
        emitter = EventEmitter()

        count = await emitter.emit(EventType.VALIDATION_STARTED, {'test': 'data'})

        assert count == 0

    @pytest.mark.asyncio
    async def test_emit_with_server(self):
        """Test emitting event with WebSocket server."""
        server = Mock()
        server.broadcast_event = AsyncMock(return_value=5)

        emitter = EventEmitter(websocket_server=server)

        count = await emitter.emit(EventType.VALIDATION_STARTED, {'test': 'data'})

        assert count == 5
        server.broadcast_event.assert_called_once()


class TestValidationEventEmitter:
    """Test validation event emitter."""

    @pytest.mark.asyncio
    async def test_emit_validation_started(self):
        """Test emitting validation started event."""
        server = Mock()
        server.broadcast_event = AsyncMock(return_value=3)

        emitter = ValidationEventEmitter(websocket_server=server)

        count = await emitter.emit_validation_started(
            validation_id='val-123',
            report_title='Test XSS',
            metadata={'severity': 'high'},
        )

        assert count == 3
        server.broadcast_event.assert_called_once()

        # Check call arguments
        call_args = server.broadcast_event.call_args
        assert call_args[0][0] == EventType.VALIDATION_STARTED
        assert call_args[0][1]['validation_id'] == 'val-123'
        assert call_args[0][1]['report_title'] == 'Test XSS'

    @pytest.mark.asyncio
    async def test_emit_validation_progress(self):
        """Test emitting validation progress event."""
        server = Mock()
        server.broadcast_event = AsyncMock(return_value=3)

        emitter = ValidationEventEmitter(websocket_server=server)

        count = await emitter.emit_validation_progress(
            validation_id='val-123',
            stage='quality_assessment',
            progress=50,
            message='Analyzing report quality',
        )

        assert count == 3
        call_args = server.broadcast_event.call_args
        assert call_args[0][1]['stage'] == 'quality_assessment'
        assert call_args[0][1]['progress'] == 50

    @pytest.mark.asyncio
    async def test_emit_validation_completed(self):
        """Test emitting validation completed event."""
        server = Mock()
        server.broadcast_event = AsyncMock(return_value=3)

        emitter = ValidationEventEmitter(websocket_server=server)

        count = await emitter.emit_validation_completed(
            validation_id='val-123',
            verdict='VALID',
            confidence=95,
            cvss_score=7.5,
        )

        assert count == 3
        call_args = server.broadcast_event.call_args
        assert call_args[0][1]['verdict'] == 'VALID'
        assert call_args[0][1]['confidence'] == 95
        assert call_args[0][1]['cvss_score'] == 7.5


class TestWorkflowEventEmitter:
    """Test workflow event emitter."""

    @pytest.mark.asyncio
    async def test_emit_workflow_created(self):
        """Test emitting workflow created event."""
        server = Mock()
        server.broadcast_event = AsyncMock(return_value=2)

        emitter = WorkflowEventEmitter(websocket_server=server)

        count = await emitter.emit_workflow_created(
            workflow_id='wf-123',
            workflow_name='Security Review',
            entity_type='report',
            entity_id='rep-456',
            created_by='user-1',
        )

        assert count == 2
        call_args = server.broadcast_event.call_args
        assert call_args[0][1]['workflow_id'] == 'wf-123'
        assert call_args[0][1]['entity_type'] == 'report'

    @pytest.mark.asyncio
    async def test_emit_workflow_state_changed(self):
        """Test emitting workflow state changed event."""
        server = Mock()
        server.broadcast_event = AsyncMock(return_value=2)

        emitter = WorkflowEventEmitter(websocket_server=server)

        count = await emitter.emit_workflow_state_changed(
            workflow_id='wf-123',
            instance_id='inst-456',
            from_state='PENDING',
            to_state='IN_PROGRESS',
            changed_by='user-1',
            action='start',
        )

        assert count == 2
        call_args = server.broadcast_event.call_args
        assert call_args[0][1]['from_state'] == 'PENDING'
        assert call_args[0][1]['to_state'] == 'IN_PROGRESS'


class TestCollaborationEventEmitter:
    """Test collaboration event emitter."""

    @pytest.mark.asyncio
    async def test_emit_comment_added(self):
        """Test emitting comment added event."""
        server = Mock()
        server.broadcast_event = AsyncMock(return_value=4)

        emitter = CollaborationEventEmitter(websocket_server=server)

        count = await emitter.emit_comment_added(
            comment_id='cmt-123',
            entity_type='report',
            entity_id='rep-456',
            user_id='user-1',
            user_name='Alice',
            content='This looks like a valid XSS',
            mentions=['user-2', 'user-3'],
        )

        assert count == 4
        call_args = server.broadcast_event.call_args
        assert call_args[0][1]['comment_id'] == 'cmt-123'
        assert call_args[0][1]['content'] == 'This looks like a valid XSS'
        assert call_args[0][2] == 'report:rep-456'  # room parameter


class TestPresenceTracker:
    """Test presence tracker."""

    @pytest.mark.asyncio
    async def test_update_presence_new_user(self):
        """Test updating presence for new user."""
        tracker = PresenceTracker()

        presence = await tracker.update_presence(
            user_id='user-1',
            status=PresenceStatus.ONLINE,
            user_name='Alice',
        )

        assert presence.user_id == 'user-1'
        assert presence.user_name == 'Alice'
        assert presence.status == PresenceStatus.ONLINE

    @pytest.mark.asyncio
    async def test_update_presence_existing_user(self):
        """Test updating presence for existing user."""
        tracker = PresenceTracker()

        await tracker.update_presence('user-1', PresenceStatus.ONLINE, user_name='Alice')
        presence = await tracker.update_presence('user-1', PresenceStatus.AWAY)

        assert presence.status == PresenceStatus.AWAY
        assert presence.user_name == 'Alice'  # Name preserved

    def test_get_presence(self):
        """Test getting user presence."""
        tracker = PresenceTracker()

        asyncio.run(tracker.update_presence('user-1', PresenceStatus.ONLINE, user_name='Alice'))

        presence = tracker.get_presence('user-1')

        assert presence is not None
        assert presence.user_id == 'user-1'

    def test_get_online_users(self):
        """Test getting online users."""
        tracker = PresenceTracker()

        asyncio.run(tracker.update_presence('user-1', PresenceStatus.ONLINE, user_name='Alice'))
        asyncio.run(tracker.update_presence('user-2', PresenceStatus.AWAY, user_name='Bob'))
        asyncio.run(tracker.update_presence('user-3', PresenceStatus.OFFLINE, user_name='Charlie'))

        online_users = tracker.get_online_users()

        assert len(online_users) == 2  # ONLINE and AWAY
        user_ids = [u.user_id for u in online_users]
        assert 'user-1' in user_ids
        assert 'user-2' in user_ids
        assert 'user-3' not in user_ids

    @pytest.mark.asyncio
    async def test_start_typing(self):
        """Test starting typing indicator."""
        tracker = PresenceTracker()

        await tracker.start_typing(
            user_id='user-1',
            user_name='Alice',
            entity_type='report',
            entity_id='rep-123',
        )

        typing_users = tracker.get_typing_users('report', 'rep-123')

        assert len(typing_users) == 1
        assert typing_users[0].user_id == 'user-1'

    @pytest.mark.asyncio
    async def test_stop_typing(self):
        """Test stopping typing indicator."""
        tracker = PresenceTracker()

        await tracker.start_typing('user-1', 'Alice', 'report', 'rep-123')
        await tracker.stop_typing('user-1', 'report', 'rep-123')

        typing_users = tracker.get_typing_users('report', 'rep-123')

        assert len(typing_users) == 0

    def test_typing_indicator_expiration(self):
        """Test typing indicator expiration."""
        indicator = TypingIndicator(
            user_id='user-1',
            user_name='Alice',
            entity_type='report',
            entity_id='rep-123',
        )

        # Fresh indicator should not be expired
        assert not indicator.is_expired(timeout_seconds=5)

        # Old indicator should be expired
        indicator.last_update = datetime.utcnow() - timedelta(seconds=10)
        assert indicator.is_expired(timeout_seconds=5)

    def test_get_stats(self):
        """Test getting presence tracker statistics."""
        tracker = PresenceTracker()

        asyncio.run(tracker.update_presence('user-1', PresenceStatus.ONLINE, user_name='Alice'))
        asyncio.run(tracker.update_presence('user-2', PresenceStatus.AWAY, user_name='Bob'))

        stats = tracker.get_stats()

        assert stats['total_users'] == 2
        assert stats['online_users'] == 2
        assert stats['status_counts']['online'] == 1
        assert stats['status_counts']['away'] == 1

