"""
GraphQL subscriptions for BountyBot.

Defines real-time subscriptions via WebSocket.
"""

import logging
import asyncio
from typing import AsyncGenerator, Optional
from datetime import datetime

from .context import GraphQLContext, require_authentication

logger = logging.getLogger(__name__)

# Try to import Strawberry
try:
    import strawberry
    from strawberry.types import Info
    STRAWBERRY_AVAILABLE = True
except ImportError:
    logger.warning("strawberry-graphql not available")
    STRAWBERRY_AVAILABLE = False
    strawberry = None
    Info = None


if STRAWBERRY_AVAILABLE:
    from .types import (
        ValidationStatusUpdate,
        MetricsUpdate
    )
    
    
    # Global event queue for broadcasting updates
    _event_queue: asyncio.Queue = asyncio.Queue()
    
    
    async def broadcast_validation_status(
        report_id: str,
        status: str,
        progress: float,
        message: Optional[str] = None
    ):
        """
        Broadcast validation status update.
        
        Args:
            report_id: Report ID
            status: Status message
            progress: Progress percentage (0-100)
            message: Optional message
        """
        update = ValidationStatusUpdate(
            report_id=report_id,
            status=status,
            progress=progress,
            message=message,
            timestamp=datetime.utcnow()
        )
        
        await _event_queue.put(('validation_status', update))
        logger.debug(f"Broadcasted validation status: {report_id} - {status}")
    
    
    async def broadcast_metrics_update(
        total_reports: int,
        valid_reports: int,
        invalid_reports: int
    ):
        """
        Broadcast metrics update.
        
        Args:
            total_reports: Total number of reports
            valid_reports: Number of valid reports
            invalid_reports: Number of invalid reports
        """
        update = MetricsUpdate(
            total_reports=total_reports,
            valid_reports=valid_reports,
            invalid_reports=invalid_reports,
            timestamp=datetime.utcnow()
        )
        
        await _event_queue.put(('metrics', update))
        logger.debug(f"Broadcasted metrics update: {total_reports} total")
    
    
    @strawberry.type
    class Subscription:
        """Root subscription type."""
        
        @strawberry.subscription
        async def validation_status_updates(
            self,
            info: Info,
            report_id: Optional[str] = None
        ) -> AsyncGenerator[ValidationStatusUpdate, None]:
            """
            Subscribe to validation status updates.
            
            Args:
                report_id: Optional report ID to filter updates
                
            Yields:
                Validation status updates
            """
            context: GraphQLContext = info.context
            
            try:
                require_authentication(context)
            except PermissionError as e:
                logger.warning(f"Unauthenticated subscription attempt: {e}")
                return
            
            logger.info(f"Client subscribed to validation status updates: report_id={report_id}")
            
            # Create a local queue for this subscription
            local_queue: asyncio.Queue = asyncio.Queue()
            
            # Background task to filter and forward events
            async def event_forwarder():
                while True:
                    try:
                        event_type, event_data = await _event_queue.get()
                        
                        if event_type == 'validation_status':
                            # Filter by report_id if specified
                            if report_id is None or event_data.report_id == report_id:
                                await local_queue.put(event_data)
                    except Exception as e:
                        logger.error(f"Event forwarder error: {e}")
                        break
            
            # Start forwarder task
            forwarder_task = asyncio.create_task(event_forwarder())
            
            try:
                # Yield updates from local queue
                while True:
                    update = await local_queue.get()
                    yield update
            except asyncio.CancelledError:
                logger.info("Subscription cancelled")
            finally:
                forwarder_task.cancel()
                logger.info("Client unsubscribed from validation status updates")
        
        @strawberry.subscription
        async def metrics_updates(
            self,
            info: Info
        ) -> AsyncGenerator[MetricsUpdate, None]:
            """
            Subscribe to metrics updates.
            
            Yields:
                Metrics updates
            """
            context: GraphQLContext = info.context
            
            try:
                require_authentication(context)
            except PermissionError as e:
                logger.warning(f"Unauthenticated subscription attempt: {e}")
                return
            
            logger.info("Client subscribed to metrics updates")
            
            # Create a local queue for this subscription
            local_queue: asyncio.Queue = asyncio.Queue()
            
            # Background task to filter and forward events
            async def event_forwarder():
                while True:
                    try:
                        event_type, event_data = await _event_queue.get()
                        
                        if event_type == 'metrics':
                            await local_queue.put(event_data)
                    except Exception as e:
                        logger.error(f"Event forwarder error: {e}")
                        break
            
            # Start forwarder task
            forwarder_task = asyncio.create_task(event_forwarder())
            
            try:
                # Yield updates from local queue
                while True:
                    update = await local_queue.get()
                    yield update
            except asyncio.CancelledError:
                logger.info("Subscription cancelled")
            finally:
                forwarder_task.cancel()
                logger.info("Client unsubscribed from metrics updates")
        
        @strawberry.subscription
        async def heartbeat(
            self,
            info: Info,
            interval: int = 5
        ) -> AsyncGenerator[str, None]:
            """
            Heartbeat subscription for testing WebSocket connection.
            
            Args:
                interval: Heartbeat interval in seconds
                
            Yields:
                Heartbeat messages
            """
            logger.info(f"Client subscribed to heartbeat: interval={interval}s")
            
            try:
                count = 0
                while True:
                    count += 1
                    yield f"Heartbeat #{count} at {datetime.utcnow().isoformat()}"
                    await asyncio.sleep(interval)
            except asyncio.CancelledError:
                logger.info("Heartbeat subscription cancelled")

else:
    # Stub when Strawberry not available
    class Subscription:
        pass
    
    async def broadcast_validation_status(*args, **kwargs):
        pass
    
    async def broadcast_metrics_update(*args, **kwargs):
        pass


__all__ = [
    'Subscription',
    'broadcast_validation_status',
    'broadcast_metrics_update'
]

