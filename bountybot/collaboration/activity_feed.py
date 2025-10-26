"""
Activity feed manager for tracking and displaying team activities.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from bountybot.collaboration.models import Activity, ActivityType


@dataclass
class ActivityFilter:
    """Filter for activity feed queries."""
    user_id: Optional[str] = None
    entity_type: Optional[str] = None
    entity_id: Optional[str] = None
    activity_types: List[ActivityType] = field(default_factory=list)
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: int = 50


class ActivityFeedManager:
    """
    Manage activity feed for team collaboration.
    
    Example:
        >>> manager = ActivityFeedManager()
        >>> 
        >>> # Record activity
        >>> activity = manager.record_activity(
        ...     activity_type=ActivityType.REPORT_VALIDATED,
        ...     entity_type="report",
        ...     entity_id="report-123",
        ...     user_id="analyst@acme.com",
        ...     user_name="Alice Analyst",
        ...     title="Report validated",
        ...     description="Report #123 validated as critical SQL injection"
        ... )
        >>> 
        >>> # Get activity feed
        >>> activities = manager.get_activity_feed(limit=20)
        >>> 
        >>> # Get user activity
        >>> user_activities = manager.get_user_activity("analyst@acme.com")
        >>> 
        >>> # Get entity activity
        >>> report_activities = manager.get_entity_activity("report", "report-123")
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize activity feed manager."""
        self.config = config or {}
        self.activities: Dict[str, Activity] = {}
    
    def record_activity(
        self,
        activity_type: ActivityType,
        entity_type: str,
        entity_id: str,
        user_id: str,
        user_name: str,
        title: str,
        description: str = "",
        metadata: Optional[Dict[str, Any]] = None
    ) -> Activity:
        """Record a new activity."""
        activity = Activity(
            activity_type=activity_type,
            entity_type=entity_type,
            entity_id=entity_id,
            user_id=user_id,
            user_name=user_name,
            title=title,
            description=description,
            metadata=metadata or {}
        )
        
        self.activities[activity.activity_id] = activity
        return activity
    
    def get_activity_feed(
        self,
        filter_params: Optional[ActivityFilter] = None
    ) -> List[Activity]:
        """Get activity feed with optional filtering."""
        if filter_params is None:
            filter_params = ActivityFilter()
        
        activities = list(self.activities.values())
        
        # Apply filters
        if filter_params.user_id:
            activities = [a for a in activities if a.user_id == filter_params.user_id]
        
        if filter_params.entity_type:
            activities = [a for a in activities if a.entity_type == filter_params.entity_type]
        
        if filter_params.entity_id:
            activities = [a for a in activities if a.entity_id == filter_params.entity_id]
        
        if filter_params.activity_types:
            activities = [a for a in activities if a.activity_type in filter_params.activity_types]
        
        if filter_params.start_date:
            activities = [a for a in activities if a.created_at >= filter_params.start_date]
        
        if filter_params.end_date:
            activities = [a for a in activities if a.created_at <= filter_params.end_date]
        
        # Sort by creation time (newest first)
        activities.sort(key=lambda a: a.created_at, reverse=True)
        
        # Apply limit
        return activities[:filter_params.limit]
    
    def get_user_activity(
        self,
        user_id: str,
        limit: int = 50
    ) -> List[Activity]:
        """Get all activities for a user."""
        filter_params = ActivityFilter(user_id=user_id, limit=limit)
        return self.get_activity_feed(filter_params)
    
    def get_entity_activity(
        self,
        entity_type: str,
        entity_id: str,
        limit: int = 50
    ) -> List[Activity]:
        """Get all activities for an entity."""
        filter_params = ActivityFilter(
            entity_type=entity_type,
            entity_id=entity_id,
            limit=limit
        )
        return self.get_activity_feed(filter_params)
    
    def get_recent_activity(
        self,
        hours: int = 24,
        limit: int = 50
    ) -> List[Activity]:
        """Get recent activities within the last N hours."""
        start_date = datetime.utcnow() - timedelta(hours=hours)
        filter_params = ActivityFilter(start_date=start_date, limit=limit)
        return self.get_activity_feed(filter_params)
    
    def get_activity_by_type(
        self,
        activity_type: ActivityType,
        limit: int = 50
    ) -> List[Activity]:
        """Get activities by type."""
        filter_params = ActivityFilter(activity_types=[activity_type], limit=limit)
        return self.get_activity_feed(filter_params)
    
    def get_activity_stats(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Get activity statistics."""
        activities = list(self.activities.values())
        
        # Apply date filters
        if start_date:
            activities = [a for a in activities if a.created_at >= start_date]
        if end_date:
            activities = [a for a in activities if a.created_at <= end_date]
        
        # Calculate stats
        stats = {
            'total_activities': len(activities),
            'unique_users': len(set(a.user_id for a in activities)),
            'unique_entities': len(set(f"{a.entity_type}:{a.entity_id}" for a in activities)),
            'activities_by_type': {},
            'activities_by_user': {},
            'activities_by_entity_type': {},
        }
        
        # Count by type
        for activity in activities:
            activity_type = activity.activity_type.value
            if activity_type not in stats['activities_by_type']:
                stats['activities_by_type'][activity_type] = 0
            stats['activities_by_type'][activity_type] += 1
        
        # Count by user
        for activity in activities:
            user_id = activity.user_id
            if user_id not in stats['activities_by_user']:
                stats['activities_by_user'][user_id] = 0
            stats['activities_by_user'][user_id] += 1
        
        # Count by entity type
        for activity in activities:
            entity_type = activity.entity_type
            if entity_type not in stats['activities_by_entity_type']:
                stats['activities_by_entity_type'][entity_type] = 0
            stats['activities_by_entity_type'][entity_type] += 1
        
        return stats
    
    def get_user_activity_summary(
        self,
        user_id: str,
        days: int = 30
    ) -> Dict[str, Any]:
        """Get activity summary for a user."""
        start_date = datetime.utcnow() - timedelta(days=days)
        activities = [
            a for a in self.activities.values()
            if a.user_id == user_id and a.created_at >= start_date
        ]
        
        summary = {
            'user_id': user_id,
            'period_days': days,
            'total_activities': len(activities),
            'activities_by_type': {},
            'activities_by_day': {},
            'most_active_day': None,
            'most_active_entity_type': None,
        }
        
        # Count by type
        for activity in activities:
            activity_type = activity.activity_type.value
            if activity_type not in summary['activities_by_type']:
                summary['activities_by_type'][activity_type] = 0
            summary['activities_by_type'][activity_type] += 1
        
        # Count by day
        for activity in activities:
            day = activity.created_at.date().isoformat()
            if day not in summary['activities_by_day']:
                summary['activities_by_day'][day] = 0
            summary['activities_by_day'][day] += 1
        
        # Find most active day
        if summary['activities_by_day']:
            summary['most_active_day'] = max(
                summary['activities_by_day'].items(),
                key=lambda x: x[1]
            )[0]
        
        # Find most active entity type
        entity_type_counts = {}
        for activity in activities:
            entity_type = activity.entity_type
            if entity_type not in entity_type_counts:
                entity_type_counts[entity_type] = 0
            entity_type_counts[entity_type] += 1
        
        if entity_type_counts:
            summary['most_active_entity_type'] = max(
                entity_type_counts.items(),
                key=lambda x: x[1]
            )[0]
        
        return summary
    
    def delete_old_activities(self, days: int = 90) -> int:
        """Delete activities older than N days."""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        old_activity_ids = [
            activity_id for activity_id, activity in self.activities.items()
            if activity.created_at < cutoff_date
        ]
        
        for activity_id in old_activity_ids:
            del self.activities[activity_id]
        
        return len(old_activity_ids)
    
    def get_activity(self, activity_id: str) -> Optional[Activity]:
        """Get a specific activity by ID."""
        return self.activities.get(activity_id)
    
    def search_activities(
        self,
        query: str,
        limit: int = 50
    ) -> List[Activity]:
        """Search activities by title or description."""
        query_lower = query.lower()
        
        matching_activities = [
            activity for activity in self.activities.values()
            if query_lower in activity.title.lower() or query_lower in activity.description.lower()
        ]
        
        # Sort by creation time (newest first)
        matching_activities.sort(key=lambda a: a.created_at, reverse=True)
        
        return matching_activities[:limit]

