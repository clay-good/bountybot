"""
GraphQL queries for BountyBot.

Defines read operations for the GraphQL API.
"""

import logging
from typing import List, Optional

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
        ValidationReportType,
        ValidationReportConnection,
        ValidationReportFilterInput,
        UserType,
        OrganizationType,
        MetricsType,
        VerdictEnum
    )
    
    
    @strawberry.type
    class Query:
        """Root query type."""
        
        @strawberry.field
        def hello(self) -> str:
            """Hello world query."""
            return "Hello from BountyBot GraphQL API!"
        
        @strawberry.field
        def version(self) -> str:
            """Get API version."""
            return "2.12.0"
        
        @strawberry.field
        async def validation_report(
            self,
            info: Info,
            id: strawberry.ID
        ) -> Optional[ValidationReportType]:
            """
            Get validation report by ID.
            
            Args:
                id: Report ID
                
            Returns:
                Validation report or None
            """
            context: GraphQLContext = info.context
            require_authentication(context)
            
            try:
                from bountybot.database.session import get_session
                from bountybot.database.models import ValidationReport
                from datetime import datetime
                
                session = get_session()
                if not session:
                    logger.warning("Database not available")
                    return None
                
                # Query database
                report = session.query(ValidationReport).filter(
                    ValidationReport.id == int(id)
                ).first()
                
                if not report:
                    return None
                
                # Convert to GraphQL type
                return ValidationReportType(
                    id=strawberry.ID(str(report.id)),
                    report_id=report.report_id,
                    title=report.title or "Untitled",
                    description=report.description,
                    verdict=VerdictEnum[report.verdict],
                    confidence=report.confidence,
                    severity=report.severity,
                    cvss_score=report.cvss_score,
                    is_duplicate=report.is_duplicate or False,
                    is_false_positive=report.is_false_positive or False,
                    priority_level=report.priority_level,
                    created_at=report.created_at or datetime.utcnow(),
                    updated_at=report.updated_at or datetime.utcnow(),
                    organization_id=context.organization_id,
                    user_id=context.user_id
                )
                
            except Exception as e:
                logger.error(f"Failed to get validation report: {e}")
                return None
        
        @strawberry.field
        async def validation_reports(
            self,
            info: Info,
            filter: Optional[ValidationReportFilterInput] = None,
            limit: int = 10,
            offset: int = 0
        ) -> ValidationReportConnection:
            """
            Get paginated validation reports.
            
            Args:
                filter: Optional filter criteria
                limit: Maximum number of results
                offset: Offset for pagination
                
            Returns:
                Paginated validation reports
            """
            context: GraphQLContext = info.context
            require_authentication(context)
            
            try:
                from bountybot.database.session import get_session
                from bountybot.database.models import ValidationReport
                from datetime import datetime
                
                session = get_session()
                if not session:
                    logger.warning("Database not available")
                    return ValidationReportConnection(
                        items=[],
                        total_count=0,
                        has_next_page=False,
                        has_previous_page=False
                    )
                
                # Build query
                query = session.query(ValidationReport)
                
                # Apply filters
                if filter:
                    if filter.verdict:
                        query = query.filter(ValidationReport.verdict == filter.verdict.value)
                    if filter.severity:
                        query = query.filter(ValidationReport.severity == filter.severity.value)
                    if filter.is_duplicate is not None:
                        query = query.filter(ValidationReport.is_duplicate == filter.is_duplicate)
                    if filter.is_false_positive is not None:
                        query = query.filter(ValidationReport.is_false_positive == filter.is_false_positive)
                    if filter.min_confidence is not None:
                        query = query.filter(ValidationReport.confidence >= filter.min_confidence)
                    if filter.max_confidence is not None:
                        query = query.filter(ValidationReport.confidence <= filter.max_confidence)
                
                # Get total count
                total_count = query.count()
                
                # Apply pagination
                reports = query.order_by(ValidationReport.created_at.desc()).limit(limit).offset(offset).all()
                
                # Convert to GraphQL types
                items = [
                    ValidationReportType(
                        id=strawberry.ID(str(report.id)),
                        report_id=report.report_id,
                        title=report.title or "Untitled",
                        description=report.description,
                        verdict=VerdictEnum[report.verdict],
                        confidence=report.confidence,
                        severity=report.severity,
                        cvss_score=report.cvss_score,
                        is_duplicate=report.is_duplicate or False,
                        is_false_positive=report.is_false_positive or False,
                        priority_level=report.priority_level,
                        created_at=report.created_at or datetime.utcnow(),
                        updated_at=report.updated_at or datetime.utcnow(),
                        organization_id=context.organization_id,
                        user_id=context.user_id
                    )
                    for report in reports
                ]
                
                return ValidationReportConnection(
                    items=items,
                    total_count=total_count,
                    has_next_page=(offset + limit) < total_count,
                    has_previous_page=offset > 0
                )
                
            except Exception as e:
                logger.error(f"Failed to get validation reports: {e}")
                return ValidationReportConnection(
                    items=[],
                    total_count=0,
                    has_next_page=False,
                    has_previous_page=False
                )
        
        @strawberry.field
        async def metrics(
            self,
            info: Info
        ) -> MetricsType:
            """
            Get validation metrics.
            
            Returns:
                Validation metrics
            """
            context: GraphQLContext = info.context
            require_authentication(context)
            
            try:
                from bountybot.database.session import get_session
                from bountybot.database.models import ValidationReport
                
                session = get_session()
                if not session:
                    logger.warning("Database not available")
                    return MetricsType(
                        total_reports=0,
                        valid_reports=0,
                        invalid_reports=0,
                        uncertain_reports=0,
                        avg_confidence=0.0,
                        avg_processing_time=0.0,
                        total_cost=0.0
                    )
                
                # Query metrics
                total_reports = session.query(ValidationReport).count()
                valid_reports = session.query(ValidationReport).filter(
                    ValidationReport.verdict == 'VALID'
                ).count()
                invalid_reports = session.query(ValidationReport).filter(
                    ValidationReport.verdict == 'INVALID'
                ).count()
                uncertain_reports = session.query(ValidationReport).filter(
                    ValidationReport.verdict == 'UNCERTAIN'
                ).count()
                
                # Calculate averages
                from sqlalchemy import func
                avg_confidence = session.query(func.avg(ValidationReport.confidence)).scalar() or 0.0
                avg_processing_time = session.query(func.avg(ValidationReport.processing_time_seconds)).scalar() or 0.0
                total_cost = session.query(func.sum(ValidationReport.total_cost)).scalar() or 0.0
                
                return MetricsType(
                    total_reports=total_reports,
                    valid_reports=valid_reports,
                    invalid_reports=invalid_reports,
                    uncertain_reports=uncertain_reports,
                    avg_confidence=float(avg_confidence),
                    avg_processing_time=float(avg_processing_time),
                    total_cost=float(total_cost)
                )
                
            except Exception as e:
                logger.error(f"Failed to get metrics: {e}")
                return MetricsType(
                    total_reports=0,
                    valid_reports=0,
                    invalid_reports=0,
                    uncertain_reports=0,
                    avg_confidence=0.0,
                    avg_processing_time=0.0,
                    total_cost=0.0
                )

else:
    # Stub when Strawberry not available
    class Query:
        pass


__all__ = ['Query']

