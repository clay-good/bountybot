"""
GraphQL mutations for BountyBot.

Defines write operations for the GraphQL API.
"""

import logging
from typing import Union

from .context import GraphQLContext, require_authentication, require_permission

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
        ValidationReportInput,
        ValidationReportType,
        SuccessResponse,
        ErrorResponse,
        VerdictEnum
    )
    
    
    @strawberry.type
    class Mutation:
        """Root mutation type."""
        
        @strawberry.mutation
        async def submit_validation(
            self,
            info: Info,
            input: ValidationReportInput
        ) -> Union[ValidationReportType, ErrorResponse]:
            """
            Submit a report for validation.
            
            Args:
                input: Validation report input
                
            Returns:
                Validation report or error
            """
            context: GraphQLContext = info.context
            
            try:
                require_authentication(context)
                require_permission(context, "reports.create")
            except PermissionError as e:
                return ErrorResponse(
                    success=False,
                    error="PermissionDenied",
                    message=str(e)
                )
            
            try:
                # Submit validation task
                from bountybot.tasks import TaskManager, TaskPriority
                
                task_manager = TaskManager()
                
                # Map priority string to enum
                priority_map = {
                    "HIGH": TaskPriority.HIGH,
                    "NORMAL": TaskPriority.NORMAL,
                    "LOW": TaskPriority.LOW
                }
                priority = priority_map.get(input.priority or "NORMAL", TaskPriority.NORMAL)
                
                # Submit task
                task_id = task_manager.submit_validation_task(
                    report_path=input.report_path,
                    codebase_path=input.codebase_path,
                    target_url=input.target_url,
                    priority=priority
                )
                
                if not task_id:
                    return ErrorResponse(
                        success=False,
                        error="TaskSubmissionFailed",
                        message="Failed to submit validation task"
                    )
                
                # Create placeholder report
                from datetime import datetime
                
                return ValidationReportType(
                    id=strawberry.ID(task_id),
                    report_id=task_id,
                    title="Validation in progress",
                    description=f"Report: {input.report_path}",
                    verdict=VerdictEnum.UNCERTAIN,
                    confidence=0.0,
                    severity=None,
                    cvss_score=None,
                    is_duplicate=False,
                    is_false_positive=False,
                    priority_level=None,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                    organization_id=context.organization_id,
                    user_id=context.user_id
                )
                
            except Exception as e:
                logger.error(f"Failed to submit validation: {e}")
                return ErrorResponse(
                    success=False,
                    error="InternalError",
                    message=f"Failed to submit validation: {str(e)}"
                )
        
        @strawberry.mutation
        async def delete_validation_report(
            self,
            info: Info,
            id: strawberry.ID
        ) -> Union[SuccessResponse, ErrorResponse]:
            """
            Delete a validation report.
            
            Args:
                id: Report ID
                
            Returns:
                Success or error response
            """
            context: GraphQLContext = info.context
            
            try:
                require_authentication(context)
                require_permission(context, "reports.delete")
            except PermissionError as e:
                return ErrorResponse(
                    success=False,
                    error="PermissionDenied",
                    message=str(e)
                )
            
            try:
                from bountybot.database.session import get_session
                from bountybot.database.models import ValidationReport
                
                session = get_session()
                if not session:
                    return ErrorResponse(
                        success=False,
                        error="DatabaseUnavailable",
                        message="Database not available"
                    )
                
                # Delete report
                report = session.query(ValidationReport).filter(
                    ValidationReport.id == int(id)
                ).first()
                
                if not report:
                    return ErrorResponse(
                        success=False,
                        error="NotFound",
                        message=f"Report not found: {id}"
                    )
                
                session.delete(report)
                session.commit()
                
                return SuccessResponse(
                    success=True,
                    message=f"Report deleted: {id}"
                )
                
            except Exception as e:
                logger.error(f"Failed to delete report: {e}")
                return ErrorResponse(
                    success=False,
                    error="InternalError",
                    message=f"Failed to delete report: {str(e)}"
                )
        
        @strawberry.mutation
        async def update_validation_report(
            self,
            info: Info,
            id: strawberry.ID,
            title: Optional[str] = None,
            description: Optional[str] = None
        ) -> Union[ValidationReportType, ErrorResponse]:
            """
            Update a validation report.
            
            Args:
                id: Report ID
                title: New title
                description: New description
                
            Returns:
                Updated report or error
            """
            context: GraphQLContext = info.context
            
            try:
                require_authentication(context)
                require_permission(context, "reports.update")
            except PermissionError as e:
                return ErrorResponse(
                    success=False,
                    error="PermissionDenied",
                    message=str(e)
                )
            
            try:
                from bountybot.database.session import get_session
                from bountybot.database.models import ValidationReport
                from datetime import datetime
                
                session = get_session()
                if not session:
                    return ErrorResponse(
                        success=False,
                        error="DatabaseUnavailable",
                        message="Database not available"
                    )
                
                # Update report
                report = session.query(ValidationReport).filter(
                    ValidationReport.id == int(id)
                ).first()
                
                if not report:
                    return ErrorResponse(
                        success=False,
                        error="NotFound",
                        message=f"Report not found: {id}"
                    )
                
                if title:
                    report.title = title
                if description:
                    report.description = description
                
                report.updated_at = datetime.utcnow()
                session.commit()
                
                # Return updated report
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
                logger.error(f"Failed to update report: {e}")
                return ErrorResponse(
                    success=False,
                    error="InternalError",
                    message=f"Failed to update report: {str(e)}"
                )

else:
    # Stub when Strawberry not available
    class Mutation:
        pass


__all__ = ['Mutation']

