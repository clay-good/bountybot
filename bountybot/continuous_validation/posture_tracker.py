"""
Security Posture Tracker

Monitors security improvements, tracks metrics, and generates trend reports.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from uuid import uuid4
from collections import defaultdict

from .models import (
    SecurityPosture,
    PostureMetrics,
    VulnerabilityLifecycle,
    VulnerabilityLifecycleState
)

logger = logging.getLogger(__name__)


class SecurityPostureTracker:
    """
    Tracks security posture over time and generates metrics and trends.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize security posture tracker.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.posture_snapshots: Dict[str, SecurityPosture] = {}
        self.snapshot_history: List[SecurityPosture] = []
        
        # Configuration
        self.snapshot_retention_days = self.config.get('snapshot_retention_days', 90)
        self.trend_analysis_window_days = self.config.get('trend_analysis_window_days', 30)
        
        logger.info("SecurityPostureTracker initialized")
    
    def create_posture_snapshot(
        self,
        lifecycles: List[VulnerabilityLifecycle],
        snapshot_id: Optional[str] = None
    ) -> SecurityPosture:
        """
        Create security posture snapshot from current vulnerability lifecycles.
        
        Args:
            lifecycles: List of vulnerability lifecycles
            snapshot_id: Optional snapshot ID
            
        Returns:
            SecurityPosture object
        """
        snapshot_id = snapshot_id or str(uuid4())
        
        # Count vulnerabilities by state
        state_counts = defaultdict(int)
        for lifecycle in lifecycles:
            state_counts[lifecycle.current_state] += 1
        
        # Count vulnerabilities by severity
        severity_counts = defaultdict(int)
        for lifecycle in lifecycles:
            severity_counts[lifecycle.severity.lower()] += 1
        
        # Create posture snapshot
        posture = SecurityPosture(
            snapshot_id=snapshot_id,
            timestamp=datetime.utcnow(),
            discovered_count=state_counts[VulnerabilityLifecycleState.DISCOVERED],
            validated_count=state_counts[VulnerabilityLifecycleState.VALIDATED],
            triaged_count=state_counts[VulnerabilityLifecycleState.TRIAGED],
            fix_in_progress_count=state_counts[VulnerabilityLifecycleState.FIX_IN_PROGRESS],
            fix_verified_count=state_counts[VulnerabilityLifecycleState.FIX_VERIFIED],
            monitoring_count=state_counts[VulnerabilityLifecycleState.MONITORING],
            regression_detected_count=state_counts[VulnerabilityLifecycleState.REGRESSION_DETECTED],
            closed_count=state_counts[VulnerabilityLifecycleState.CLOSED],
            critical_count=severity_counts['critical'],
            high_count=severity_counts['high'],
            medium_count=severity_counts['medium'],
            low_count=severity_counts['low'],
            info_count=severity_counts['info']
        )
        
        # Calculate metrics
        posture.metrics = self._calculate_metrics(lifecycles)
        
        # Analyze trends if we have previous snapshots
        if self.snapshot_history:
            posture.trend_direction, posture.trend_details = self._analyze_trends(posture)
        
        # Store snapshot
        self.posture_snapshots[snapshot_id] = posture
        self.snapshot_history.append(posture)
        
        # Clean up old snapshots
        self._cleanup_old_snapshots()
        
        logger.info(f"Created security posture snapshot {snapshot_id}")
        return posture
    
    def _calculate_metrics(self, lifecycles: List[VulnerabilityLifecycle]) -> PostureMetrics:
        """
        Calculate security posture metrics.
        
        Args:
            lifecycles: List of vulnerability lifecycles
            
        Returns:
            PostureMetrics object
        """
        metrics = PostureMetrics()
        
        if not lifecycles:
            return metrics
        
        # Time metrics
        time_to_validate_list = [lc.time_to_validate for lc in lifecycles if lc.time_to_validate is not None]
        time_to_triage_list = [lc.time_to_triage for lc in lifecycles if lc.time_to_triage is not None]
        time_to_fix_list = [lc.time_to_fix for lc in lifecycles if lc.time_to_fix is not None]
        time_to_verify_list = [lc.time_to_verify for lc in lifecycles if lc.time_to_verify is not None]
        total_lifecycle_list = [lc.total_lifecycle_time for lc in lifecycles if lc.total_lifecycle_time is not None]
        
        if time_to_validate_list:
            metrics.avg_time_to_validate = sum(time_to_validate_list) / len(time_to_validate_list)
        if time_to_triage_list:
            metrics.avg_time_to_triage = sum(time_to_triage_list) / len(time_to_triage_list)
        if time_to_fix_list:
            metrics.avg_time_to_fix = sum(time_to_fix_list) / len(time_to_fix_list)
        if time_to_verify_list:
            metrics.avg_time_to_verify = sum(time_to_verify_list) / len(time_to_verify_list)
        if total_lifecycle_list:
            metrics.avg_total_lifecycle_time = sum(total_lifecycle_list) / len(total_lifecycle_list)
        
        # Fix metrics
        verified_count = sum(1 for lc in lifecycles if lc.current_state == VulnerabilityLifecycleState.FIX_VERIFIED)
        closed_count = sum(1 for lc in lifecycles if lc.current_state == VulnerabilityLifecycleState.CLOSED)
        regression_count = sum(1 for lc in lifecycles if lc.regression_detected_count > 0)
        false_positive_count = sum(1 for lc in lifecycles if lc.current_state == VulnerabilityLifecycleState.FALSE_POSITIVE)
        
        total_fixed = verified_count + closed_count
        if total_fixed > 0:
            metrics.fix_success_rate = verified_count / total_fixed
            metrics.regression_rate = regression_count / total_fixed
        
        total_validated = sum(1 for lc in lifecycles if lc.validated_at is not None)
        if total_validated > 0:
            metrics.false_positive_rate = false_positive_count / total_validated
        
        # Velocity metrics (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        
        discovered_last_30 = sum(1 for lc in lifecycles if lc.discovered_at >= thirty_days_ago)
        fixed_last_30 = sum(1 for lc in lifecycles if lc.fix_completed_at and lc.fix_completed_at >= thirty_days_ago)
        verified_last_30 = sum(1 for lc in lifecycles if lc.last_verification and lc.last_verification >= thirty_days_ago)
        
        metrics.vulnerabilities_discovered_per_day = discovered_last_30 / 30.0
        metrics.vulnerabilities_fixed_per_day = fixed_last_30 / 30.0
        metrics.vulnerabilities_verified_per_day = verified_last_30 / 30.0
        
        # Quality metrics
        confidence_scores = [lc.confidence_score for lc in lifecycles if lc.confidence_score is not None]
        priority_scores = [lc.priority_score for lc in lifecycles if lc.priority_score is not None]
        
        if confidence_scores:
            metrics.avg_confidence_score = sum(confidence_scores) / len(confidence_scores)
        if priority_scores:
            metrics.avg_priority_score = sum(priority_scores) / len(priority_scores)
        
        # Coverage metrics
        monitoring_enabled = sum(1 for lc in lifecycles if lc.monitoring_enabled)
        if total_fixed > 0:
            metrics.monitoring_coverage = monitoring_enabled / total_fixed
        
        verified_fixes = sum(1 for lc in lifecycles if lc.verification_count > 0)
        if total_fixed > 0:
            metrics.verification_coverage = verified_fixes / total_fixed
        
        return metrics
    
    def _analyze_trends(self, current_posture: SecurityPosture) -> tuple[str, Dict[str, Any]]:
        """
        Analyze trends by comparing with previous snapshots.
        
        Args:
            current_posture: Current posture snapshot
            
        Returns:
            Tuple of (trend_direction, trend_details)
        """
        # Get previous snapshot from trend analysis window
        window_start = datetime.utcnow() - timedelta(days=self.trend_analysis_window_days)
        previous_snapshots = [s for s in self.snapshot_history if s.timestamp >= window_start]
        
        if not previous_snapshots:
            return "stable", {}
        
        # Compare with oldest snapshot in window
        previous = previous_snapshots[0]
        
        # Calculate changes
        total_open_current = (
            current_posture.discovered_count +
            current_posture.validated_count +
            current_posture.triaged_count +
            current_posture.fix_in_progress_count
        )
        
        total_open_previous = (
            previous.discovered_count +
            previous.validated_count +
            previous.triaged_count +
            previous.fix_in_progress_count
        )
        
        critical_high_current = current_posture.critical_count + current_posture.high_count
        critical_high_previous = previous.critical_count + previous.high_count
        
        # Determine trend direction
        trend_details = {
            'total_open_change': total_open_current - total_open_previous,
            'critical_high_change': critical_high_current - critical_high_previous,
            'closed_change': current_posture.closed_count - previous.closed_count,
            'regression_change': current_posture.regression_detected_count - previous.regression_detected_count,
            'comparison_period_days': self.trend_analysis_window_days
        }
        
        # Improving if: fewer open vulns, fewer critical/high, more closed, fewer regressions
        improving_score = 0
        if total_open_current < total_open_previous:
            improving_score += 2
        if critical_high_current < critical_high_previous:
            improving_score += 2
        if current_posture.closed_count > previous.closed_count:
            improving_score += 1
        if current_posture.regression_detected_count <= previous.regression_detected_count:
            improving_score += 1
        
        if improving_score >= 4:
            trend_direction = "improving"
        elif improving_score <= 2:
            trend_direction = "degrading"
        else:
            trend_direction = "stable"
        
        trend_details['improving_score'] = improving_score
        trend_details['trend_direction'] = trend_direction
        
        return trend_direction, trend_details
    
    def get_posture_snapshot(self, snapshot_id: str) -> Optional[SecurityPosture]:
        """Get posture snapshot by ID."""
        return self.posture_snapshots.get(snapshot_id)
    
    def get_latest_posture(self) -> Optional[SecurityPosture]:
        """Get most recent posture snapshot."""
        if not self.snapshot_history:
            return None
        return self.snapshot_history[-1]
    
    def get_posture_history(
        self,
        days: Optional[int] = None,
        limit: Optional[int] = None
    ) -> List[SecurityPosture]:
        """
        Get posture snapshot history.
        
        Args:
            days: Optional number of days to look back
            limit: Optional maximum number of snapshots
            
        Returns:
            List of SecurityPosture snapshots
        """
        snapshots = self.snapshot_history
        
        if days:
            cutoff = datetime.utcnow() - timedelta(days=days)
            snapshots = [s for s in snapshots if s.timestamp >= cutoff]
        
        if limit:
            snapshots = snapshots[-limit:]
        
        return snapshots
    
    def generate_trend_report(self, days: int = 30) -> Dict[str, Any]:
        """
        Generate comprehensive trend report.
        
        Args:
            days: Number of days to analyze
            
        Returns:
            Trend report dictionary
        """
        snapshots = self.get_posture_history(days=days)
        
        if not snapshots:
            return {
                'error': 'No snapshots available for trend analysis',
                'days_analyzed': days
            }
        
        # Calculate trends
        first_snapshot = snapshots[0]
        last_snapshot = snapshots[-1]
        
        report = {
            'analysis_period': {
                'start_date': first_snapshot.timestamp.isoformat(),
                'end_date': last_snapshot.timestamp.isoformat(),
                'days': days,
                'snapshots_analyzed': len(snapshots)
            },
            'vulnerability_trends': {
                'discovered': {
                    'start': first_snapshot.discovered_count,
                    'end': last_snapshot.discovered_count,
                    'change': last_snapshot.discovered_count - first_snapshot.discovered_count
                },
                'closed': {
                    'start': first_snapshot.closed_count,
                    'end': last_snapshot.closed_count,
                    'change': last_snapshot.closed_count - first_snapshot.closed_count
                },
                'regression_detected': {
                    'start': first_snapshot.regression_detected_count,
                    'end': last_snapshot.regression_detected_count,
                    'change': last_snapshot.regression_detected_count - first_snapshot.regression_detected_count
                }
            },
            'severity_trends': {
                'critical': {
                    'start': first_snapshot.critical_count,
                    'end': last_snapshot.critical_count,
                    'change': last_snapshot.critical_count - first_snapshot.critical_count
                },
                'high': {
                    'start': first_snapshot.high_count,
                    'end': last_snapshot.high_count,
                    'change': last_snapshot.high_count - first_snapshot.high_count
                }
            },
            'metrics_trends': {
                'fix_success_rate': {
                    'start': first_snapshot.metrics.fix_success_rate,
                    'end': last_snapshot.metrics.fix_success_rate,
                    'change': (last_snapshot.metrics.fix_success_rate or 0) - (first_snapshot.metrics.fix_success_rate or 0)
                },
                'regression_rate': {
                    'start': first_snapshot.metrics.regression_rate,
                    'end': last_snapshot.metrics.regression_rate,
                    'change': (last_snapshot.metrics.regression_rate or 0) - (first_snapshot.metrics.regression_rate or 0)
                },
                'avg_time_to_fix': {
                    'start': first_snapshot.metrics.avg_time_to_fix,
                    'end': last_snapshot.metrics.avg_time_to_fix,
                    'change': (last_snapshot.metrics.avg_time_to_fix or 0) - (first_snapshot.metrics.avg_time_to_fix or 0)
                }
            },
            'overall_trend': last_snapshot.trend_direction,
            'trend_details': last_snapshot.trend_details
        }
        
        return report
    
    def _cleanup_old_snapshots(self):
        """Remove snapshots older than retention period."""
        cutoff = datetime.utcnow() - timedelta(days=self.snapshot_retention_days)
        
        # Remove from history
        self.snapshot_history = [s for s in self.snapshot_history if s.timestamp >= cutoff]
        
        # Remove from dict
        old_ids = [sid for sid, snapshot in self.posture_snapshots.items() if snapshot.timestamp < cutoff]
        for sid in old_ids:
            del self.posture_snapshots[sid]
        
        if old_ids:
            logger.info(f"Cleaned up {len(old_ids)} old posture snapshots")

