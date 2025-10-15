import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class ReportMetrics:
    """Metrics for bug bounty reports."""
    
    # Counts
    total_reports: int = 0
    valid_reports: int = 0
    invalid_reports: int = 0
    uncertain_reports: int = 0
    duplicate_reports: int = 0
    
    # By severity
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    # By vulnerability type
    vulnerability_distribution: Dict[str, int] = field(default_factory=dict)
    
    # Quality metrics
    average_confidence: float = 0.0
    average_cvss_score: float = 0.0
    average_priority_score: float = 0.0
    
    # Processing metrics
    average_processing_time: float = 0.0
    total_processing_time: float = 0.0
    
    # Cost metrics
    total_ai_cost: float = 0.0
    average_ai_cost: float = 0.0
    
    # Time metrics
    first_report_date: Optional[datetime] = None
    last_report_date: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'total_reports': self.total_reports,
            'valid_reports': self.valid_reports,
            'invalid_reports': self.invalid_reports,
            'uncertain_reports': self.uncertain_reports,
            'duplicate_reports': self.duplicate_reports,
            'by_severity': {
                'critical': self.critical_count,
                'high': self.high_count,
                'medium': self.medium_count,
                'low': self.low_count,
                'info': self.info_count
            },
            'vulnerability_distribution': self.vulnerability_distribution,
            'quality_metrics': {
                'average_confidence': round(self.average_confidence, 2),
                'average_cvss_score': round(self.average_cvss_score, 2),
                'average_priority_score': round(self.average_priority_score, 2)
            },
            'processing_metrics': {
                'average_processing_time': round(self.average_processing_time, 2),
                'total_processing_time': round(self.total_processing_time, 2)
            },
            'cost_metrics': {
                'total_ai_cost': round(self.total_ai_cost, 2),
                'average_ai_cost': round(self.average_ai_cost, 4)
            },
            'time_range': {
                'first_report': self.first_report_date.isoformat() if self.first_report_date else None,
                'last_report': self.last_report_date.isoformat() if self.last_report_date else None
            }
        }


@dataclass
class ResearcherMetrics:
    """Metrics for bug bounty researchers."""
    
    researcher_id: str
    username: str
    
    # Report counts
    total_reports: int = 0
    valid_reports: int = 0
    invalid_reports: int = 0
    duplicate_reports: int = 0
    
    # Quality metrics
    quality_score: float = 0.0
    average_confidence: float = 0.0
    false_positive_rate: float = 0.0
    duplicate_rate: float = 0.0
    
    # Severity distribution
    critical_reports: int = 0
    high_reports: int = 0
    medium_reports: int = 0
    low_reports: int = 0
    
    # Time metrics
    first_report_date: Optional[datetime] = None
    last_report_date: Optional[datetime] = None
    average_time_between_reports: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'researcher_id': self.researcher_id,
            'username': self.username,
            'report_counts': {
                'total': self.total_reports,
                'valid': self.valid_reports,
                'invalid': self.invalid_reports,
                'duplicate': self.duplicate_reports
            },
            'quality_metrics': {
                'quality_score': round(self.quality_score, 2),
                'average_confidence': round(self.average_confidence, 2),
                'false_positive_rate': round(self.false_positive_rate, 2),
                'duplicate_rate': round(self.duplicate_rate, 2)
            },
            'severity_distribution': {
                'critical': self.critical_reports,
                'high': self.high_reports,
                'medium': self.medium_reports,
                'low': self.low_reports
            },
            'time_metrics': {
                'first_report': self.first_report_date.isoformat() if self.first_report_date else None,
                'last_report': self.last_report_date.isoformat() if self.last_report_date else None,
                'average_time_between_reports': round(self.average_time_between_reports, 2)
            }
        }


@dataclass
class SystemMetrics:
    """System-wide performance metrics."""
    
    # Performance
    total_validations: int = 0
    average_validation_time: float = 0.0
    total_validation_time: float = 0.0
    
    # AI usage
    total_ai_calls: int = 0
    total_ai_cost: float = 0.0
    cache_hit_rate: float = 0.0
    
    # Detection rates
    false_positive_detection_rate: float = 0.0
    duplicate_detection_rate: float = 0.0
    attack_chain_detection_rate: float = 0.0
    
    # Priority distribution
    critical_priority_count: int = 0
    high_priority_count: int = 0
    medium_priority_count: int = 0
    low_priority_count: int = 0
    
    # Time range
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'performance': {
                'total_validations': self.total_validations,
                'average_validation_time': round(self.average_validation_time, 2),
                'total_validation_time': round(self.total_validation_time, 2)
            },
            'ai_usage': {
                'total_calls': self.total_ai_calls,
                'total_cost': round(self.total_ai_cost, 2),
                'cache_hit_rate': round(self.cache_hit_rate, 2)
            },
            'detection_rates': {
                'false_positive': round(self.false_positive_detection_rate, 2),
                'duplicate': round(self.duplicate_detection_rate, 2),
                'attack_chain': round(self.attack_chain_detection_rate, 2)
            },
            'priority_distribution': {
                'critical': self.critical_priority_count,
                'high': self.high_priority_count,
                'medium': self.medium_priority_count,
                'low': self.low_priority_count
            },
            'time_range': {
                'start': self.start_time.isoformat() if self.start_time else None,
                'end': self.end_time.isoformat() if self.end_time else None
            }
        }


class MetricsCollector:
    """
    Collects and aggregates metrics from validation results.
    """
    
    def __init__(self):
        self.report_metrics = ReportMetrics()
        self.researcher_metrics: Dict[str, ResearcherMetrics] = {}
        self.system_metrics = SystemMetrics()
    
    def collect_from_result(self, result: Any):
        """
        Collect metrics from a validation result.
        
        Args:
            result: ValidationResult object
        """
        # Update report metrics
        self._update_report_metrics(result)
        
        # Update researcher metrics
        if hasattr(result.report, 'researcher_id') and result.report.researcher_id:
            self._update_researcher_metrics(result)
        
        # Update system metrics
        self._update_system_metrics(result)
    
    def _update_report_metrics(self, result: Any):
        """Update report-level metrics."""
        metrics = self.report_metrics
        
        metrics.total_reports += 1
        
        # Count by verdict
        if hasattr(result, 'verdict'):
            verdict = str(result.verdict).upper()
            if verdict == 'VALID':
                metrics.valid_reports += 1
            elif verdict == 'INVALID':
                metrics.invalid_reports += 1
            elif verdict == 'UNCERTAIN':
                metrics.uncertain_reports += 1
        
        # Count duplicates
        if hasattr(result, 'duplicate_check') and result.duplicate_check:
            if result.duplicate_check.is_duplicate:
                metrics.duplicate_reports += 1
        
        # Count by severity
        if hasattr(result.report, 'severity'):
            severity = str(result.report.severity).upper()
            if 'CRITICAL' in severity:
                metrics.critical_count += 1
            elif 'HIGH' in severity:
                metrics.high_count += 1
            elif 'MEDIUM' in severity:
                metrics.medium_count += 1
            elif 'LOW' in severity:
                metrics.low_count += 1
            else:
                metrics.info_count += 1
        
        # Vulnerability distribution
        if hasattr(result.report, 'vulnerability_type') and result.report.vulnerability_type:
            vuln_type = result.report.vulnerability_type
            metrics.vulnerability_distribution[vuln_type] = \
                metrics.vulnerability_distribution.get(vuln_type, 0) + 1
        
        # Quality metrics (running average)
        if hasattr(result, 'confidence') and result.confidence:
            metrics.average_confidence = (
                (metrics.average_confidence * (metrics.total_reports - 1) + result.confidence) /
                metrics.total_reports
            )
        
        if hasattr(result, 'cvss_score') and result.cvss_score:
            score = result.cvss_score.base_score if hasattr(result.cvss_score, 'base_score') else result.cvss_score
            metrics.average_cvss_score = (
                (metrics.average_cvss_score * (metrics.total_reports - 1) + score) /
                metrics.total_reports
            )
        
        if hasattr(result, 'priority_score') and result.priority_score:
            score = result.priority_score.overall_score if hasattr(result.priority_score, 'overall_score') else result.priority_score
            metrics.average_priority_score = (
                (metrics.average_priority_score * (metrics.total_reports - 1) + score) /
                metrics.total_reports
            )
        
        # Processing metrics
        if hasattr(result, 'processing_time_seconds') and result.processing_time_seconds:
            metrics.total_processing_time += result.processing_time_seconds
            metrics.average_processing_time = metrics.total_processing_time / metrics.total_reports
        
        # Cost metrics
        if hasattr(result, 'ai_cost') and result.ai_cost:
            metrics.total_ai_cost += result.ai_cost
            metrics.average_ai_cost = metrics.total_ai_cost / metrics.total_reports
        
        # Time tracking
        if hasattr(result.report, 'submission_date') and result.report.submission_date:
            date = result.report.submission_date
            if not metrics.first_report_date or date < metrics.first_report_date:
                metrics.first_report_date = date
            if not metrics.last_report_date or date > metrics.last_report_date:
                metrics.last_report_date = date
    
    def _update_researcher_metrics(self, result: Any):
        """Update researcher-level metrics."""
        researcher_id = str(result.report.researcher_id)
        
        if researcher_id not in self.researcher_metrics:
            username = getattr(result.report, 'researcher_username', f'researcher_{researcher_id}')
            self.researcher_metrics[researcher_id] = ResearcherMetrics(
                researcher_id=researcher_id,
                username=username
            )
        
        metrics = self.researcher_metrics[researcher_id]
        metrics.total_reports += 1
        
        # Update counts by verdict
        if hasattr(result, 'verdict'):
            verdict = str(result.verdict).upper()
            if verdict == 'VALID':
                metrics.valid_reports += 1
            elif verdict == 'INVALID':
                metrics.invalid_reports += 1
        
        # Update duplicate count
        if hasattr(result, 'duplicate_check') and result.duplicate_check:
            if result.duplicate_check.is_duplicate:
                metrics.duplicate_reports += 1
        
        # Calculate rates
        if metrics.total_reports > 0:
            metrics.false_positive_rate = (metrics.invalid_reports / metrics.total_reports) * 100
            metrics.duplicate_rate = (metrics.duplicate_reports / metrics.total_reports) * 100
            metrics.quality_score = max(0, 100 - metrics.false_positive_rate - metrics.duplicate_rate)
    
    def _update_system_metrics(self, result: Any):
        """Update system-level metrics."""
        metrics = self.system_metrics
        
        metrics.total_validations += 1
        
        # Processing time
        if hasattr(result, 'processing_time_seconds') and result.processing_time_seconds:
            metrics.total_validation_time += result.processing_time_seconds
            metrics.average_validation_time = metrics.total_validation_time / metrics.total_validations
        
        # AI usage
        if hasattr(result, 'ai_cost') and result.ai_cost:
            metrics.total_ai_cost += result.ai_cost
        
        # Priority distribution
        if hasattr(result, 'priority_score') and result.priority_score:
            priority = str(result.priority_score.priority_level).lower() if hasattr(result.priority_score, 'priority_level') else 'medium'
            if 'critical' in priority:
                metrics.critical_priority_count += 1
            elif 'high' in priority:
                metrics.high_priority_count += 1
            elif 'medium' in priority:
                metrics.medium_priority_count += 1
            else:
                metrics.low_priority_count += 1
    
    def get_report_metrics(self) -> ReportMetrics:
        """Get report metrics."""
        return self.report_metrics
    
    def get_researcher_metrics(self, researcher_id: Optional[str] = None) -> Dict[str, ResearcherMetrics]:
        """Get researcher metrics."""
        if researcher_id:
            return {researcher_id: self.researcher_metrics.get(researcher_id)}
        return self.researcher_metrics
    
    def get_system_metrics(self) -> SystemMetrics:
        """Get system metrics."""
        return self.system_metrics
    
    def get_top_researchers(self, limit: int = 10) -> List[ResearcherMetrics]:
        """Get top researchers by quality score."""
        researchers = sorted(
            self.researcher_metrics.values(),
            key=lambda r: r.quality_score,
            reverse=True
        )
        return researchers[:limit]
    
    def export_all(self) -> Dict[str, Any]:
        """Export all metrics as dictionary."""
        return {
            'report_metrics': self.report_metrics.to_dict(),
            'researcher_metrics': {
                rid: metrics.to_dict()
                for rid, metrics in self.researcher_metrics.items()
            },
            'system_metrics': self.system_metrics.to_dict(),
            'top_researchers': [
                r.to_dict() for r in self.get_top_researchers()
            ]
        }

