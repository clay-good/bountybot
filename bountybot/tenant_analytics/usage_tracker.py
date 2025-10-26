"""
Usage Tracker

Tracks and aggregates tenant usage metrics across all dimensions.
"""

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from bountybot.tenant_analytics.models import (
    UsageEvent,
    UsageMetric,
    UsageMetricType,
    UsageAggregation,
    AggregationPeriod,
)


logger = logging.getLogger(__name__)


class UsageTracker:
    """Tracks tenant usage metrics."""
    
    def __init__(self):
        """Initialize usage tracker."""
        self.events: List[UsageEvent] = []
        self.metrics: Dict[str, Dict[UsageMetricType, List[UsageMetric]]] = defaultdict(lambda: defaultdict(list))
        self.stats = {
            'total_events': 0,
            'events_by_type': defaultdict(int),
            'events_by_tenant': defaultdict(int),
        }
    
    def track_event(
        self,
        tenant_id: str,
        metric_type: UsageMetricType,
        value: float = 1.0,
        metadata: Optional[Dict] = None,
    ) -> UsageEvent:
        """
        Track a usage event.
        
        Args:
            tenant_id: Tenant identifier
            metric_type: Type of metric
            value: Metric value
            metadata: Additional metadata
            
        Returns:
            Created usage event
        """
        event = UsageEvent(
            tenant_id=tenant_id,
            metric_type=metric_type,
            value=value,
            metadata=metadata or {},
        )
        
        self.events.append(event)
        
        # Update statistics
        self.stats['total_events'] += 1
        self.stats['events_by_type'][metric_type] += 1
        self.stats['events_by_tenant'][tenant_id] += 1
        
        logger.debug(f"Tracked event: {metric_type.value} for tenant {tenant_id}, value={value}")
        
        return event
    
    def track_api_call(self, tenant_id: str, endpoint: str, response_time_ms: float) -> UsageEvent:
        """Track an API call."""
        return self.track_event(
            tenant_id=tenant_id,
            metric_type=UsageMetricType.API_CALLS,
            value=1.0,
            metadata={'endpoint': endpoint, 'response_time_ms': response_time_ms},
        )
    
    def track_validation(self, tenant_id: str, validation_type: str, duration_seconds: float) -> UsageEvent:
        """Track a validation."""
        return self.track_event(
            tenant_id=tenant_id,
            metric_type=UsageMetricType.VALIDATIONS,
            value=1.0,
            metadata={'validation_type': validation_type, 'duration_seconds': duration_seconds},
        )
    
    def track_ai_tokens(self, tenant_id: str, tokens: int, provider: str, model: str) -> UsageEvent:
        """Track AI token usage."""
        return self.track_event(
            tenant_id=tenant_id,
            metric_type=UsageMetricType.AI_TOKENS,
            value=float(tokens),
            metadata={'provider': provider, 'model': model},
        )
    
    def track_storage(self, tenant_id: str, bytes_used: int, storage_type: str) -> UsageEvent:
        """Track storage usage."""
        return self.track_event(
            tenant_id=tenant_id,
            metric_type=UsageMetricType.STORAGE_BYTES,
            value=float(bytes_used),
            metadata={'storage_type': storage_type},
        )
    
    def track_active_user(self, tenant_id: str, user_id: str) -> UsageEvent:
        """Track an active user."""
        return self.track_event(
            tenant_id=tenant_id,
            metric_type=UsageMetricType.USERS_ACTIVE,
            value=1.0,
            metadata={'user_id': user_id},
        )
    
    def track_feature_adoption(self, tenant_id: str, feature_name: str) -> UsageEvent:
        """Track feature adoption."""
        return self.track_event(
            tenant_id=tenant_id,
            metric_type=UsageMetricType.FEATURES_ADOPTED,
            value=1.0,
            metadata={'feature_name': feature_name},
        )
    
    def aggregate_metrics(
        self,
        tenant_id: str,
        period: AggregationPeriod,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> UsageAggregation:
        """
        Aggregate usage metrics for a tenant.
        
        Args:
            tenant_id: Tenant identifier
            period: Aggregation period
            start_time: Start of period (default: 24 hours ago)
            end_time: End of period (default: now)
            
        Returns:
            Usage aggregation
        """
        if end_time is None:
            end_time = datetime.utcnow()
        
        if start_time is None:
            # Default to appropriate period
            if period == AggregationPeriod.HOURLY:
                start_time = end_time - timedelta(hours=1)
            elif period == AggregationPeriod.DAILY:
                start_time = end_time - timedelta(days=1)
            elif period == AggregationPeriod.WEEKLY:
                start_time = end_time - timedelta(weeks=1)
            elif period == AggregationPeriod.MONTHLY:
                start_time = end_time - timedelta(days=30)
            elif period == AggregationPeriod.QUARTERLY:
                start_time = end_time - timedelta(days=90)
            else:  # YEARLY
                start_time = end_time - timedelta(days=365)
        
        # Filter events for this tenant and time period
        tenant_events = [
            e for e in self.events
            if e.tenant_id == tenant_id
            and start_time <= e.timestamp <= end_time
        ]
        
        # Group by metric type
        events_by_type = defaultdict(list)
        for event in tenant_events:
            events_by_type[event.metric_type].append(event)
        
        # Calculate aggregations
        metrics = {}
        for metric_type, events in events_by_type.items():
            values = [e.value for e in events]
            
            if values:
                metric = UsageMetric(
                    tenant_id=tenant_id,
                    metric_type=metric_type,
                    period=period,
                    period_start=start_time,
                    period_end=end_time,
                    total=sum(values),
                    average=sum(values) / len(values),
                    minimum=min(values),
                    maximum=max(values),
                    count=len(values),
                )
                
                metrics[metric_type] = metric
                
                # Store metric
                self.metrics[tenant_id][metric_type].append(metric)
        
        aggregation = UsageAggregation(
            tenant_id=tenant_id,
            period=period,
            metrics=metrics,
            total_events=len(tenant_events),
            period_start=start_time,
            period_end=end_time,
        )
        
        logger.info(
            f"Aggregated {len(tenant_events)} events for tenant {tenant_id} "
            f"over {period.value} period"
        )
        
        return aggregation
    
    def get_tenant_usage(
        self,
        tenant_id: str,
        metric_type: Optional[UsageMetricType] = None,
        period: Optional[AggregationPeriod] = None,
    ) -> List[UsageMetric]:
        """
        Get usage metrics for a tenant.
        
        Args:
            tenant_id: Tenant identifier
            metric_type: Filter by metric type (optional)
            period: Filter by period (optional)
            
        Returns:
            List of usage metrics
        """
        if metric_type:
            metrics = self.metrics[tenant_id].get(metric_type, [])
        else:
            # Get all metrics for tenant
            metrics = []
            for metric_list in self.metrics[tenant_id].values():
                metrics.extend(metric_list)
        
        # Filter by period if specified
        if period:
            metrics = [m for m in metrics if m.period == period]
        
        return metrics
    
    def get_usage_trend(
        self,
        tenant_id: str,
        metric_type: UsageMetricType,
        num_periods: int = 7,
    ) -> List[UsageMetric]:
        """
        Get usage trend over time.
        
        Args:
            tenant_id: Tenant identifier
            metric_type: Type of metric
            num_periods: Number of periods to retrieve
            
        Returns:
            List of usage metrics ordered by time
        """
        metrics = self.get_tenant_usage(tenant_id, metric_type)
        
        # Sort by period start time
        metrics.sort(key=lambda m: m.period_start)
        
        # Return last N periods
        return metrics[-num_periods:]
    
    def get_top_tenants(
        self,
        metric_type: UsageMetricType,
        limit: int = 10,
    ) -> List[tuple]:
        """
        Get top tenants by usage.
        
        Args:
            metric_type: Type of metric
            limit: Number of tenants to return
            
        Returns:
            List of (tenant_id, total_usage) tuples
        """
        tenant_usage = defaultdict(float)
        
        for tenant_id, metrics_by_type in self.metrics.items():
            if metric_type in metrics_by_type:
                total = sum(m.total for m in metrics_by_type[metric_type])
                tenant_usage[tenant_id] = total
        
        # Sort by usage descending
        sorted_tenants = sorted(
            tenant_usage.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return sorted_tenants[:limit]
    
    def get_stats(self) -> Dict:
        """Get usage tracker statistics."""
        return {
            'total_events': self.stats['total_events'],
            'events_by_type': dict(self.stats['events_by_type']),
            'events_by_tenant': dict(self.stats['events_by_tenant']),
            'total_tenants': len(self.metrics),
            'total_metrics': sum(
                len(metrics)
                for tenant_metrics in self.metrics.values()
                for metrics in tenant_metrics.values()
            ),
        }

