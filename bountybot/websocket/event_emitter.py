"""
Event emitters for real-time streaming of validation, workflow, and system events.
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime

from bountybot.websocket.models import EventType
from bountybot.websocket.server import WebSocketServer


logger = logging.getLogger(__name__)


class EventEmitter:
    """
    Base event emitter for broadcasting events through WebSocket.
    """
    
    def __init__(self, websocket_server: Optional[WebSocketServer] = None):
        """
        Initialize event emitter.
        
        Args:
            websocket_server: WebSocket server instance for broadcasting
        """
        self.websocket_server = websocket_server
        self.enabled = websocket_server is not None
    
    async def emit(self, event_type: EventType, data: Dict[str, Any],
                  room: Optional[str] = None) -> int:
        """
        Emit event to WebSocket subscribers.
        
        Args:
            event_type: Type of event
            data: Event data
            room: Optional room to broadcast to
            
        Returns:
            Number of connections that received the event
        """
        if not self.enabled or not self.websocket_server:
            return 0
        
        try:
            return await self.websocket_server.broadcast_event(event_type, data, room)
        except Exception as e:
            logger.error(f"Error emitting event {event_type.value}: {e}")
            return 0


class ValidationEventEmitter(EventEmitter):
    """
    Event emitter for validation progress and results.
    """
    
    async def emit_validation_started(self, validation_id: str, report_title: str,
                                     metadata: Optional[Dict[str, Any]] = None) -> int:
        """Emit validation started event."""
        data = {
            'validation_id': validation_id,
            'report_title': report_title,
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': metadata or {},
        }
        return await self.emit(EventType.VALIDATION_STARTED, data)
    
    async def emit_validation_progress(self, validation_id: str, stage: str,
                                      progress: int, message: str,
                                      metadata: Optional[Dict[str, Any]] = None) -> int:
        """
        Emit validation progress event.
        
        Args:
            validation_id: Validation ID
            stage: Current stage (parsing, quality_assessment, plausibility, etc.)
            progress: Progress percentage (0-100)
            message: Progress message
            metadata: Additional metadata
        """
        data = {
            'validation_id': validation_id,
            'stage': stage,
            'progress': progress,
            'message': message,
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': metadata or {},
        }
        return await self.emit(EventType.VALIDATION_PROGRESS, data)
    
    async def emit_validation_completed(self, validation_id: str, verdict: str,
                                       confidence: int, cvss_score: Optional[float] = None,
                                       metadata: Optional[Dict[str, Any]] = None) -> int:
        """Emit validation completed event."""
        data = {
            'validation_id': validation_id,
            'verdict': verdict,
            'confidence': confidence,
            'cvss_score': cvss_score,
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': metadata or {},
        }
        return await self.emit(EventType.VALIDATION_COMPLETED, data)
    
    async def emit_validation_failed(self, validation_id: str, error: str,
                                    metadata: Optional[Dict[str, Any]] = None) -> int:
        """Emit validation failed event."""
        data = {
            'validation_id': validation_id,
            'error': error,
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': metadata or {},
        }
        return await self.emit(EventType.VALIDATION_FAILED, data)


class WorkflowEventEmitter(EventEmitter):
    """
    Event emitter for workflow state changes and task updates.
    """
    
    async def emit_workflow_created(self, workflow_id: str, workflow_name: str,
                                   entity_type: str, entity_id: str,
                                   created_by: str) -> int:
        """Emit workflow created event."""
        data = {
            'workflow_id': workflow_id,
            'workflow_name': workflow_name,
            'entity_type': entity_type,
            'entity_id': entity_id,
            'created_by': created_by,
            'timestamp': datetime.utcnow().isoformat(),
        }
        return await self.emit(EventType.WORKFLOW_CREATED, data)
    
    async def emit_workflow_state_changed(self, workflow_id: str, instance_id: str,
                                         from_state: str, to_state: str,
                                         changed_by: str, action: str) -> int:
        """Emit workflow state changed event."""
        data = {
            'workflow_id': workflow_id,
            'instance_id': instance_id,
            'from_state': from_state,
            'to_state': to_state,
            'action': action,
            'changed_by': changed_by,
            'timestamp': datetime.utcnow().isoformat(),
        }
        return await self.emit(EventType.WORKFLOW_STATE_CHANGED, data)
    
    async def emit_task_assigned(self, task_id: str, workflow_id: str,
                                task_name: str, assigned_to: str,
                                assigned_by: str, priority: str) -> int:
        """Emit task assigned event."""
        data = {
            'task_id': task_id,
            'workflow_id': workflow_id,
            'task_name': task_name,
            'assigned_to': assigned_to,
            'assigned_by': assigned_by,
            'priority': priority,
            'timestamp': datetime.utcnow().isoformat(),
        }
        return await self.emit(EventType.WORKFLOW_TASK_ASSIGNED, data)
    
    async def emit_task_completed(self, task_id: str, workflow_id: str,
                                 task_name: str, completed_by: str) -> int:
        """Emit task completed event."""
        data = {
            'task_id': task_id,
            'workflow_id': workflow_id,
            'task_name': task_name,
            'completed_by': completed_by,
            'timestamp': datetime.utcnow().isoformat(),
        }
        return await self.emit(EventType.WORKFLOW_TASK_COMPLETED, data)


class CollaborationEventEmitter(EventEmitter):
    """
    Event emitter for collaboration events (comments, mentions, reactions).
    """
    
    async def emit_comment_added(self, comment_id: str, entity_type: str,
                                entity_id: str, user_id: str, user_name: str,
                                content: str, mentions: list) -> int:
        """Emit comment added event."""
        data = {
            'comment_id': comment_id,
            'entity_type': entity_type,
            'entity_id': entity_id,
            'user_id': user_id,
            'user_name': user_name,
            'content': content,
            'mentions': mentions,
            'timestamp': datetime.utcnow().isoformat(),
        }
        
        # Broadcast to entity room
        room = f"{entity_type}:{entity_id}"
        return await self.emit(EventType.COMMENT_ADDED, data, room)
    
    async def emit_comment_updated(self, comment_id: str, entity_type: str,
                                  entity_id: str, user_id: str,
                                  new_content: str) -> int:
        """Emit comment updated event."""
        data = {
            'comment_id': comment_id,
            'entity_type': entity_type,
            'entity_id': entity_id,
            'user_id': user_id,
            'new_content': new_content,
            'timestamp': datetime.utcnow().isoformat(),
        }
        
        room = f"{entity_type}:{entity_id}"
        return await self.emit(EventType.COMMENT_UPDATED, data, room)
    
    async def emit_mention_created(self, mention_id: str, mentioned_user_id: str,
                                  comment_id: str, entity_type: str,
                                  entity_id: str, mentioned_by: str) -> int:
        """Emit mention created event."""
        data = {
            'mention_id': mention_id,
            'mentioned_user_id': mentioned_user_id,
            'comment_id': comment_id,
            'entity_type': entity_type,
            'entity_id': entity_id,
            'mentioned_by': mentioned_by,
            'timestamp': datetime.utcnow().isoformat(),
        }
        return await self.emit(EventType.MENTION_CREATED, data)
    
    async def emit_reaction_added(self, reaction_id: str, comment_id: str,
                                 user_id: str, emoji: str) -> int:
        """Emit reaction added event."""
        data = {
            'reaction_id': reaction_id,
            'comment_id': comment_id,
            'user_id': user_id,
            'emoji': emoji,
            'timestamp': datetime.utcnow().isoformat(),
        }
        return await self.emit(EventType.REACTION_ADDED, data)


class SystemEventEmitter(EventEmitter):
    """
    Event emitter for system health, metrics, and alerts.
    """
    
    async def emit_health_update(self, status: str, components: Dict[str, str],
                                metadata: Optional[Dict[str, Any]] = None) -> int:
        """Emit system health update."""
        data = {
            'status': status,
            'components': components,
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': metadata or {},
        }
        return await self.emit(EventType.SYSTEM_HEALTH_UPDATE, data)
    
    async def emit_metrics_update(self, metrics: Dict[str, Any]) -> int:
        """Emit system metrics update."""
        data = {
            'metrics': metrics,
            'timestamp': datetime.utcnow().isoformat(),
        }
        return await self.emit(EventType.SYSTEM_METRICS_UPDATE, data)
    
    async def emit_alert(self, alert_type: str, severity: str, message: str,
                        metadata: Optional[Dict[str, Any]] = None) -> int:
        """Emit system alert."""
        data = {
            'alert_type': alert_type,
            'severity': severity,
            'message': message,
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': metadata or {},
        }
        return await self.emit(EventType.SYSTEM_ALERT, data)

