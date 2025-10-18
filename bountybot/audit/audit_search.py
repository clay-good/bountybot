"""
Audit Search

Advanced search and filtering for audit logs.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from .models import (
    AuditEvent,
    AuditQuery,
    AuditEventType,
    AuditEventCategory,
    AuditSeverity
)


class AuditSearch:
    """
    Advanced audit log search engine.
    
    Features:
    - Time range filtering
    - Multi-field filtering
    - Text search
    - Sorting and pagination
    - Export capabilities
    """
    
    def __init__(self, log_dir: str = "./audit_logs"):
        self.log_dir = Path(log_dir)
    
    def search(self, query: AuditQuery) -> List[AuditEvent]:
        """Search audit logs with query."""
        events = []
        
        # Load events from log files
        for log_file in self._get_log_files(query.start_time, query.end_time):
            events.extend(self._load_events_from_file(log_file))
        
        # Apply filters
        filtered_events = self._apply_filters(events, query)
        
        # Sort events
        sorted_events = self._sort_events(filtered_events, query.sort_by, query.sort_order)
        
        # Apply pagination
        paginated_events = sorted_events[query.offset:query.offset + query.limit]
        
        return paginated_events
    
    def count(self, query: AuditQuery) -> int:
        """Count events matching query."""
        events = []
        
        for log_file in self._get_log_files(query.start_time, query.end_time):
            events.extend(self._load_events_from_file(log_file))
        
        filtered_events = self._apply_filters(events, query)
        return len(filtered_events)
    
    def aggregate_by_category(self, query: AuditQuery) -> Dict[str, int]:
        """Aggregate events by category."""
        events = []
        
        for log_file in self._get_log_files(query.start_time, query.end_time):
            events.extend(self._load_events_from_file(log_file))
        
        filtered_events = self._apply_filters(events, query)
        
        aggregation = {}
        for event in filtered_events:
            category = event.category.value
            aggregation[category] = aggregation.get(category, 0) + 1
        
        return aggregation
    
    def aggregate_by_severity(self, query: AuditQuery) -> Dict[str, int]:
        """Aggregate events by severity."""
        events = []
        
        for log_file in self._get_log_files(query.start_time, query.end_time):
            events.extend(self._load_events_from_file(log_file))
        
        filtered_events = self._apply_filters(events, query)
        
        aggregation = {}
        for event in filtered_events:
            severity = event.severity.value
            aggregation[severity] = aggregation.get(severity, 0) + 1
        
        return aggregation
    
    def aggregate_by_user(self, query: AuditQuery) -> Dict[str, int]:
        """Aggregate events by user."""
        events = []
        
        for log_file in self._get_log_files(query.start_time, query.end_time):
            events.extend(self._load_events_from_file(log_file))
        
        filtered_events = self._apply_filters(events, query)
        
        aggregation = {}
        for event in filtered_events:
            user = event.username or event.user_id or 'unknown'
            aggregation[user] = aggregation.get(user, 0) + 1
        
        return aggregation
    
    def export_to_json(self, query: AuditQuery, output_file: str):
        """Export search results to JSON."""
        events = self.search(query)
        
        with open(output_file, 'w') as f:
            json.dump([event.to_dict() for event in events], f, indent=2)
    
    def export_to_csv(self, query: AuditQuery, output_file: str):
        """Export search results to CSV."""
        events = self.search(query)
        
        if not events:
            return
        
        import csv
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'event_id', 'timestamp', 'event_type', 'category', 'severity',
                'user_id', 'username', 'org_id', 'action', 'resource_type',
                'resource_id', 'ip_address', 'success', 'error_message'
            ])
            
            writer.writeheader()
            for event in events:
                writer.writerow({
                    'event_id': event.event_id,
                    'timestamp': event.timestamp.isoformat(),
                    'event_type': event.event_type.value,
                    'category': event.category.value,
                    'severity': event.severity.value,
                    'user_id': event.user_id or '',
                    'username': event.username or '',
                    'org_id': event.org_id or '',
                    'action': event.action,
                    'resource_type': event.resource_type or '',
                    'resource_id': event.resource_id or '',
                    'ip_address': event.ip_address or '',
                    'success': event.success,
                    'error_message': event.error_message or ''
                })
    
    def _get_log_files(
        self,
        start_time: Optional[datetime],
        end_time: Optional[datetime]
    ) -> List[Path]:
        """Get log files within time range."""
        if not self.log_dir.exists():
            return []

        log_files = sorted(self.log_dir.glob("audit_*.jsonl"))

        if not start_time and not end_time:
            return log_files

        # Filter by date range
        filtered_files = []
        for log_file in log_files:
            # Extract date from filename
            date_str = log_file.stem.replace('audit_', '')
            try:
                file_date = datetime.strptime(date_str, "%Y-%m-%d")

                # More lenient date filtering - include files that might contain events in range
                if start_time:
                    # Include file if it's on or after the start date
                    file_end = file_date.replace(hour=23, minute=59, second=59, microsecond=999999)
                    if file_end < start_time:
                        continue

                if end_time:
                    # Include file if it's on or before the end date
                    file_start = file_date.replace(hour=0, minute=0, second=0, microsecond=0)
                    if file_start > end_time:
                        continue

                filtered_files.append(log_file)
            except ValueError:
                # If filename doesn't match expected format, skip it
                continue

        return filtered_files
    
    def _load_events_from_file(self, log_file: Path) -> List[AuditEvent]:
        """Load events from log file."""
        events = []
        
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    event = self._dict_to_event(data)
                    events.append(event)
                except (json.JSONDecodeError, KeyError):
                    continue
        
        return events
    
    def _dict_to_event(self, data: Dict[str, Any]) -> AuditEvent:
        """Convert dictionary to AuditEvent."""
        return AuditEvent(
            event_id=data['event_id'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            event_type=AuditEventType(data['event_type']),
            category=AuditEventCategory(data['category']),
            severity=AuditSeverity(data['severity']),
            user_id=data.get('user_id'),
            username=data.get('username'),
            org_id=data.get('org_id'),
            ip_address=data.get('ip_address'),
            user_agent=data.get('user_agent'),
            action=data.get('action', ''),
            resource_type=data.get('resource_type'),
            resource_id=data.get('resource_id'),
            details=data.get('details', {}),
            metadata=data.get('metadata', {}),
            request_id=data.get('request_id'),
            session_id=data.get('session_id'),
            api_endpoint=data.get('api_endpoint'),
            http_method=data.get('http_method'),
            success=data.get('success', True),
            error_message=data.get('error_message'),
            signature=data.get('signature'),
            previous_event_hash=data.get('previous_event_hash'),
            compliance_tags=data.get('compliance_tags', []),
            retention_days=data.get('retention_days', 2555)
        )
    
    def _apply_filters(self, events: List[AuditEvent], query: AuditQuery) -> List[AuditEvent]:
        """Apply query filters to events."""
        filtered = events
        
        # Time range filter
        if query.start_time:
            filtered = [e for e in filtered if e.timestamp >= query.start_time]
        if query.end_time:
            filtered = [e for e in filtered if e.timestamp <= query.end_time]
        
        # Event type filter
        if query.event_types:
            filtered = [e for e in filtered if e.event_type in query.event_types]
        
        # Category filter
        if query.categories:
            filtered = [e for e in filtered if e.category in query.categories]
        
        # Severity filter
        if query.severities:
            filtered = [e for e in filtered if e.severity in query.severities]
        
        # User filter
        if query.user_ids:
            filtered = [e for e in filtered if e.user_id in query.user_ids]
        
        # Organization filter
        if query.org_ids:
            filtered = [e for e in filtered if e.org_id in query.org_ids]
        
        # Resource type filter
        if query.resource_types:
            filtered = [e for e in filtered if e.resource_type in query.resource_types]
        
        # Resource ID filter
        if query.resource_ids:
            filtered = [e for e in filtered if e.resource_id in query.resource_ids]
        
        # IP address filter
        if query.ip_addresses:
            filtered = [e for e in filtered if e.ip_address in query.ip_addresses]
        
        # Success filter
        if query.success_only is not None:
            filtered = [e for e in filtered if e.success == query.success_only]
        
        # Text search
        if query.text_search:
            search_term = query.text_search.lower()
            filtered = [
                e for e in filtered
                if search_term in e.action.lower()
                or search_term in str(e.details).lower()
                or search_term in (e.username or '').lower()
            ]
        
        return filtered
    
    def _sort_events(
        self,
        events: List[AuditEvent],
        sort_by: str,
        sort_order: str
    ) -> List[AuditEvent]:
        """Sort events."""
        reverse = (sort_order == 'desc')
        
        if sort_by == 'timestamp':
            return sorted(events, key=lambda e: e.timestamp, reverse=reverse)
        elif sort_by == 'severity':
            severity_order = {
                AuditSeverity.INFO: 0,
                AuditSeverity.LOW: 1,
                AuditSeverity.MEDIUM: 2,
                AuditSeverity.HIGH: 3,
                AuditSeverity.CRITICAL: 4
            }
            return sorted(events, key=lambda e: severity_order[e.severity], reverse=reverse)
        else:
            return events

