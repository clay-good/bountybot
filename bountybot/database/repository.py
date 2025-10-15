"""
Repository Pattern for Database Access

Provides clean, high-level APIs for database operations.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy import func, desc, and_, or_
from sqlalchemy.orm import Session

from .models import (
    Report, ValidationResult, Researcher, AuditLog, Metric,
    VerdictEnum, SeverityEnum, PriorityEnum, StatusEnum
)

logger = logging.getLogger(__name__)


class ReportRepository:
    """Repository for report operations."""
    
    def __init__(self, session: Session):
        self.session = session
    
    def create(self, report_data: Dict[str, Any]) -> Report:
        """Create a new report."""
        report = Report(**report_data)
        self.session.add(report)
        self.session.flush()  # Get ID without committing
        logger.info(f"Created report: {report.id} - {report.title}")
        return report
    
    def get_by_id(self, report_id: int) -> Optional[Report]:
        """Get report by ID."""
        return self.session.query(Report).filter(Report.id == report_id).first()
    
    def get_by_external_id(self, external_id: str) -> Optional[Report]:
        """Get report by external ID (from bug bounty platform)."""
        return self.session.query(Report).filter(Report.external_id == external_id).first()
    
    def get_all(self, limit: int = 100, offset: int = 0) -> List[Report]:
        """Get all reports with pagination."""
        return self.session.query(Report)\
            .order_by(desc(Report.submission_date))\
            .limit(limit)\
            .offset(offset)\
            .all()
    
    def get_by_status(self, status: StatusEnum, limit: int = 100) -> List[Report]:
        """Get reports by status."""
        return self.session.query(Report)\
            .filter(Report.status == status)\
            .order_by(desc(Report.submission_date))\
            .limit(limit)\
            .all()
    
    def get_by_severity(self, severity: SeverityEnum, limit: int = 100) -> List[Report]:
        """Get reports by severity."""
        return self.session.query(Report)\
            .filter(Report.severity == severity)\
            .order_by(desc(Report.submission_date))\
            .limit(limit)\
            .all()
    
    def get_by_researcher(self, researcher_id: int, limit: int = 100) -> List[Report]:
        """Get reports by researcher."""
        return self.session.query(Report)\
            .filter(Report.researcher_id == researcher_id)\
            .order_by(desc(Report.submission_date))\
            .limit(limit)\
            .all()
    
    def get_pending_validation(self, limit: int = 50) -> List[Report]:
        """Get reports pending validation."""
        return self.session.query(Report)\
            .filter(Report.status == StatusEnum.PENDING)\
            .outerjoin(ValidationResult)\
            .filter(ValidationResult.id == None)\
            .order_by(Report.submission_date)\
            .limit(limit)\
            .all()
    
    def search(self, query: str, limit: int = 50) -> List[Report]:
        """Search reports by title or description."""
        search_pattern = f"%{query}%"
        return self.session.query(Report)\
            .filter(
                or_(
                    Report.title.ilike(search_pattern),
                    Report.impact_description.ilike(search_pattern)
                )
            )\
            .order_by(desc(Report.submission_date))\
            .limit(limit)\
            .all()
    
    def update_status(self, report_id: int, status: StatusEnum, assigned_to: Optional[str] = None):
        """Update report status."""
        report = self.get_by_id(report_id)
        if report:
            report.status = status
            if assigned_to:
                report.assigned_to = assigned_to
            if status == StatusEnum.RESOLVED:
                report.resolution_date = datetime.utcnow()
            self.session.flush()
            logger.info(f"Updated report {report_id} status to {status.value}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get report statistics."""
        total = self.session.query(func.count(Report.id)).scalar()
        
        by_status = dict(
            self.session.query(Report.status, func.count(Report.id))
            .group_by(Report.status)
            .all()
        )
        
        by_severity = dict(
            self.session.query(Report.severity, func.count(Report.id))
            .group_by(Report.severity)
            .all()
        )
        
        return {
            'total_reports': total,
            'by_status': {k.value: v for k, v in by_status.items() if k},
            'by_severity': {k.value: v for k, v in by_severity.items() if k}
        }


class ValidationResultRepository:
    """Repository for validation result operations."""
    
    def __init__(self, session: Session):
        self.session = session
    
    def create(self, result_data: Dict[str, Any]) -> ValidationResult:
        """Create a new validation result."""
        result = ValidationResult(**result_data)
        self.session.add(result)
        self.session.flush()
        logger.info(f"Created validation result for report {result.report_id}")
        return result
    
    def get_by_id(self, result_id: int) -> Optional[ValidationResult]:
        """Get validation result by ID."""
        return self.session.query(ValidationResult).filter(ValidationResult.id == result_id).first()
    
    def get_by_report_id(self, report_id: int) -> Optional[ValidationResult]:
        """Get latest validation result for a report."""
        return self.session.query(ValidationResult)\
            .filter(ValidationResult.report_id == report_id)\
            .order_by(desc(ValidationResult.validated_at))\
            .first()
    
    def get_all_by_report_id(self, report_id: int) -> List[ValidationResult]:
        """Get all validation results for a report (history)."""
        return self.session.query(ValidationResult)\
            .filter(ValidationResult.report_id == report_id)\
            .order_by(desc(ValidationResult.validated_at))\
            .all()
    
    def get_by_verdict(self, verdict: VerdictEnum, limit: int = 100) -> List[ValidationResult]:
        """Get validation results by verdict."""
        return self.session.query(ValidationResult)\
            .filter(ValidationResult.verdict == verdict)\
            .order_by(desc(ValidationResult.validated_at))\
            .limit(limit)\
            .all()
    
    def get_by_priority(self, priority: PriorityEnum, limit: int = 100) -> List[ValidationResult]:
        """Get validation results by priority level."""
        return self.session.query(ValidationResult)\
            .filter(ValidationResult.priority_level == priority)\
            .order_by(desc(ValidationResult.priority_score))\
            .limit(limit)\
            .all()
    
    def get_high_priority(self, min_score: float = 70.0, limit: int = 50) -> List[ValidationResult]:
        """Get high-priority validation results."""
        return self.session.query(ValidationResult)\
            .filter(
                and_(
                    ValidationResult.priority_score >= min_score,
                    ValidationResult.verdict == VerdictEnum.VALID
                )
            )\
            .order_by(desc(ValidationResult.priority_score))\
            .limit(limit)\
            .all()
    
    def get_duplicates(self, limit: int = 100) -> List[ValidationResult]:
        """Get reports marked as duplicates."""
        return self.session.query(ValidationResult)\
            .filter(ValidationResult.is_duplicate == True)\
            .order_by(desc(ValidationResult.validated_at))\
            .limit(limit)\
            .all()
    
    def get_false_positives(self, min_confidence: float = 70.0, limit: int = 100) -> List[ValidationResult]:
        """Get likely false positives."""
        return self.session.query(ValidationResult)\
            .filter(ValidationResult.false_positive_confidence >= min_confidence)\
            .order_by(desc(ValidationResult.false_positive_confidence))\
            .limit(limit)\
            .all()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get validation statistics."""
        total = self.session.query(func.count(ValidationResult.id)).scalar()
        
        by_verdict = dict(
            self.session.query(ValidationResult.verdict, func.count(ValidationResult.id))
            .group_by(ValidationResult.verdict)
            .all()
        )
        
        by_priority = dict(
            self.session.query(ValidationResult.priority_level, func.count(ValidationResult.id))
            .group_by(ValidationResult.priority_level)
            .all()
        )
        
        avg_confidence = self.session.query(func.avg(ValidationResult.confidence)).scalar()
        avg_priority = self.session.query(func.avg(ValidationResult.priority_score)).scalar()
        
        duplicate_count = self.session.query(func.count(ValidationResult.id))\
            .filter(ValidationResult.is_duplicate == True)\
            .scalar()
        
        return {
            'total_validations': total,
            'by_verdict': {k.value: v for k, v in by_verdict.items() if k},
            'by_priority': {k.value: v for k, v in by_priority.items() if k},
            'average_confidence': round(avg_confidence, 2) if avg_confidence else 0,
            'average_priority_score': round(avg_priority, 2) if avg_priority else 0,
            'duplicate_count': duplicate_count,
            'duplicate_rate': round(duplicate_count / total * 100, 2) if total > 0 else 0
        }


class ResearcherRepository:
    """Repository for researcher operations."""
    
    def __init__(self, session: Session):
        self.session = session
    
    def create(self, researcher_data: Dict[str, Any]) -> Researcher:
        """Create a new researcher."""
        researcher = Researcher(**researcher_data)
        self.session.add(researcher)
        self.session.flush()
        logger.info(f"Created researcher: {researcher.id} - {researcher.username}")
        return researcher
    
    def get_by_id(self, researcher_id: int) -> Optional[Researcher]:
        """Get researcher by ID."""
        return self.session.query(Researcher).filter(Researcher.id == researcher_id).first()
    
    def get_by_username(self, username: str) -> Optional[Researcher]:
        """Get researcher by username."""
        return self.session.query(Researcher).filter(Researcher.username == username).first()
    
    def get_by_external_id(self, external_id: str) -> Optional[Researcher]:
        """Get researcher by external ID."""
        return self.session.query(Researcher).filter(Researcher.external_id == external_id).first()
    
    def get_or_create(self, username: str, external_id: Optional[str] = None) -> Researcher:
        """Get existing researcher or create new one."""
        researcher = self.get_by_username(username)
        if not researcher:
            researcher = self.create({
                'username': username,
                'external_id': external_id
            })
        return researcher
    
    def update_statistics(self, researcher_id: int, validation_result: ValidationResult):
        """Update researcher statistics based on validation result."""
        researcher = self.get_by_id(researcher_id)
        if not researcher:
            return
        
        researcher.total_reports += 1
        
        if validation_result.verdict == VerdictEnum.VALID:
            researcher.valid_reports += 1
        elif validation_result.verdict == VerdictEnum.INVALID:
            researcher.invalid_reports += 1
        
        if validation_result.is_duplicate:
            researcher.duplicate_reports += 1
        
        # Update quality metrics
        if researcher.valid_reports > 0:
            researcher.average_confidence = self.session.query(func.avg(ValidationResult.confidence))\
                .join(Report, ValidationResult.report_id == Report.id)\
                .filter(
                    and_(
                        Report.researcher_id == researcher_id,
                        ValidationResult.verdict == VerdictEnum.VALID
                    )
                )\
                .scalar()
        
        if researcher.total_reports > 0:
            researcher.false_positive_rate = (researcher.invalid_reports / researcher.total_reports) * 100
        
        # Calculate quality score (0-100)
        valid_rate = (researcher.valid_reports / researcher.total_reports) * 100 if researcher.total_reports > 0 else 0
        duplicate_penalty = (researcher.duplicate_reports / researcher.total_reports) * 20 if researcher.total_reports > 0 else 0
        researcher.quality_score = max(0, valid_rate - duplicate_penalty)
        
        self.session.flush()
        logger.info(f"Updated researcher {researcher_id} statistics")

    def get_top_researchers(self, limit: int = 10) -> List[Researcher]:
        """Get top researchers by quality score."""
        return self.session.query(Researcher)\
            .filter(Researcher.total_reports >= 5)\
            .order_by(desc(Researcher.quality_score))\
            .limit(limit)\
            .all()

    def get_statistics(self) -> Dict[str, Any]:
        """Get researcher statistics."""
        total = self.session.query(func.count(Researcher.id)).scalar()

        avg_quality = self.session.query(func.avg(Researcher.quality_score)).scalar()
        avg_reports = self.session.query(func.avg(Researcher.total_reports)).scalar()

        return {
            'total_researchers': total,
            'average_quality_score': round(avg_quality, 2) if avg_quality else 0,
            'average_reports_per_researcher': round(avg_reports, 2) if avg_reports else 0
        }


class MetricsRepository:
    """Repository for metrics operations."""

    def __init__(self, session: Session):
        self.session = session

    def record(self, metric_name: str, value: float, dimensions: Optional[Dict[str, Any]] = None, unit: str = "count"):
        """Record a metric."""
        metric = Metric(
            metric_name=metric_name,
            metric_value=value,
            dimensions=dimensions or {},
            unit=unit
        )
        self.session.add(metric)
        self.session.flush()

    def get_time_series(
        self,
        metric_name: str,
        start_time: datetime,
        end_time: datetime,
        dimensions: Optional[Dict[str, Any]] = None
    ) -> List[Metric]:
        """Get time series data for a metric."""
        query = self.session.query(Metric)\
            .filter(
                and_(
                    Metric.metric_name == metric_name,
                    Metric.timestamp >= start_time,
                    Metric.timestamp <= end_time
                )
            )

        if dimensions:
            # Filter by dimensions (this is simplified - real implementation would need JSON querying)
            for key, value in dimensions.items():
                query = query.filter(Metric.dimensions.contains({key: value}))

        return query.order_by(Metric.timestamp).all()

    def get_aggregate(
        self,
        metric_name: str,
        start_time: datetime,
        end_time: datetime,
        aggregation: str = "sum"
    ) -> float:
        """Get aggregated metric value."""
        query = self.session.query(Metric)\
            .filter(
                and_(
                    Metric.metric_name == metric_name,
                    Metric.timestamp >= start_time,
                    Metric.timestamp <= end_time
                )
            )

        if aggregation == "sum":
            result = query.with_entities(func.sum(Metric.metric_value)).scalar()
        elif aggregation == "avg":
            result = query.with_entities(func.avg(Metric.metric_value)).scalar()
        elif aggregation == "max":
            result = query.with_entities(func.max(Metric.metric_value)).scalar()
        elif aggregation == "min":
            result = query.with_entities(func.min(Metric.metric_value)).scalar()
        elif aggregation == "count":
            result = query.count()
        else:
            raise ValueError(f"Unknown aggregation: {aggregation}")

        return float(result) if result else 0.0

    def get_recent_metrics(self, hours: int = 24, limit: int = 100) -> List[Metric]:
        """Get recent metrics."""
        start_time = datetime.utcnow() - timedelta(hours=hours)
        return self.session.query(Metric)\
            .filter(Metric.timestamp >= start_time)\
            .order_by(desc(Metric.timestamp))\
            .limit(limit)\
            .all()


class AuditLogRepository:
    """Repository for audit log operations."""

    def __init__(self, session: Session):
        self.session = session

    def log(
        self,
        action: str,
        resource_type: str,
        resource_id: Optional[int] = None,
        user: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        result: str = "success"
    ):
        """Create an audit log entry."""
        log_entry = AuditLog(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            user=user,
            details=details or {},
            result=result
        )
        self.session.add(log_entry)
        self.session.flush()

    def get_by_resource(self, resource_type: str, resource_id: int, limit: int = 50) -> List[AuditLog]:
        """Get audit logs for a specific resource."""
        return self.session.query(AuditLog)\
            .filter(
                and_(
                    AuditLog.resource_type == resource_type,
                    AuditLog.resource_id == resource_id
                )
            )\
            .order_by(desc(AuditLog.timestamp))\
            .limit(limit)\
            .all()

    def get_by_action(self, action: str, limit: int = 100) -> List[AuditLog]:
        """Get audit logs by action type."""
        return self.session.query(AuditLog)\
            .filter(AuditLog.action == action)\
            .order_by(desc(AuditLog.timestamp))\
            .limit(limit)\
            .all()

    def get_recent(self, hours: int = 24, limit: int = 100) -> List[AuditLog]:
        """Get recent audit logs."""
        start_time = datetime.utcnow() - timedelta(hours=hours)
        return self.session.query(AuditLog)\
            .filter(AuditLog.timestamp >= start_time)\
            .order_by(desc(AuditLog.timestamp))\
            .limit(limit)\
            .all()

