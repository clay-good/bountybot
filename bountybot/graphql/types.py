"""
GraphQL types for BountyBot.

Defines GraphQL object types using Strawberry.
"""

import logging
from datetime import datetime
from typing import Optional, List
from enum import Enum

logger = logging.getLogger(__name__)

# Try to import Strawberry
try:
    import strawberry
    from strawberry.types import Info
    STRAWBERRY_AVAILABLE = True
except ImportError:
    logger.warning("strawberry-graphql package not installed. Install with: pip install 'strawberry-graphql[fastapi]'")
    STRAWBERRY_AVAILABLE = False
    strawberry = None
    Info = None


if STRAWBERRY_AVAILABLE:
    @strawberry.enum
    class VerdictEnum(Enum):
        """Validation verdict enum."""
        VALID = "VALID"
        INVALID = "INVALID"
        UNCERTAIN = "UNCERTAIN"
    
    
    @strawberry.enum
    class SeverityEnum(Enum):
        """Severity enum."""
        CRITICAL = "CRITICAL"
        HIGH = "HIGH"
        MEDIUM = "MEDIUM"
        LOW = "LOW"
        INFO = "INFO"
    
    
    @strawberry.enum
    class PriorityLevelEnum(Enum):
        """Priority level enum."""
        P0 = "P0"
        P1 = "P1"
        P2 = "P2"
        P3 = "P3"
        P4 = "P4"
    
    
    @strawberry.type
    class ValidationResultType:
        """Validation result type."""
        verdict: VerdictEnum
        confidence: float
        severity: Optional[SeverityEnum]
        cvss_score: Optional[float]
        cvss_vector: Optional[str]
        is_duplicate: bool
        is_false_positive: bool
        exploit_complexity: Optional[str]
        priority_level: Optional[PriorityLevelEnum]
        processing_time_seconds: float
        total_cost: float
        reasoning: Optional[str]
    
    
    @strawberry.type
    class ValidationReportType:
        """Validation report type."""
        id: strawberry.ID
        report_id: str
        title: str
        description: Optional[str]
        verdict: VerdictEnum
        confidence: float
        severity: Optional[SeverityEnum]
        cvss_score: Optional[float]
        is_duplicate: bool
        is_false_positive: bool
        priority_level: Optional[PriorityLevelEnum]
        created_at: datetime
        updated_at: datetime
        organization_id: Optional[str]
        user_id: Optional[str]
        
        @strawberry.field
        def formatted_created_at(self) -> str:
            """Get formatted creation date."""
            return self.created_at.isoformat()
        
        @strawberry.field
        def formatted_updated_at(self) -> str:
            """Get formatted update date."""
            return self.updated_at.isoformat()
    
    
    @strawberry.type
    class UserType:
        """User type."""
        id: strawberry.ID
        username: str
        email: str
        full_name: Optional[str]
        role: str
        is_active: bool
        created_at: datetime
        organization_id: Optional[str]
        
        @strawberry.field
        def reports_count(self, info: Info) -> int:
            """Get count of user's reports."""
            # This would query the database
            return 0
    
    
    @strawberry.type
    class OrganizationType:
        """Organization type."""
        id: strawberry.ID
        name: str
        slug: str
        is_active: bool
        created_at: datetime
        
        @strawberry.field
        def users_count(self, info: Info) -> int:
            """Get count of organization's users."""
            return 0
        
        @strawberry.field
        def reports_count(self, info: Info) -> int:
            """Get count of organization's reports."""
            return 0
    
    
    @strawberry.type
    class MetricsType:
        """Metrics type."""
        total_reports: int
        valid_reports: int
        invalid_reports: int
        uncertain_reports: int
        avg_confidence: float
        avg_processing_time: float
        total_cost: float
        
        @strawberry.field
        def valid_percentage(self) -> float:
            """Calculate percentage of valid reports."""
            if self.total_reports == 0:
                return 0.0
            return (self.valid_reports / self.total_reports) * 100
        
        @strawberry.field
        def invalid_percentage(self) -> float:
            """Calculate percentage of invalid reports."""
            if self.total_reports == 0:
                return 0.0
            return (self.invalid_reports / self.total_reports) * 100
    
    
    @strawberry.type
    class ValidationStatusUpdate:
        """Real-time validation status update."""
        report_id: str
        status: str
        progress: float
        message: Optional[str]
        timestamp: datetime
        
        @strawberry.field
        def formatted_timestamp(self) -> str:
            """Get formatted timestamp."""
            return self.timestamp.isoformat()
    
    
    @strawberry.type
    class MetricsUpdate:
        """Real-time metrics update."""
        total_reports: int
        valid_reports: int
        invalid_reports: int
        timestamp: datetime
    
    
    @strawberry.input
    class ValidationReportInput:
        """Input for creating validation report."""
        report_path: str
        codebase_path: Optional[str] = None
        target_url: Optional[str] = None
        priority: Optional[str] = "NORMAL"
    
    
    @strawberry.input
    class ValidationReportFilterInput:
        """Filter input for validation reports."""
        verdict: Optional[VerdictEnum] = None
        severity: Optional[SeverityEnum] = None
        is_duplicate: Optional[bool] = None
        is_false_positive: Optional[bool] = None
        organization_id: Optional[str] = None
        user_id: Optional[str] = None
        min_confidence: Optional[float] = None
        max_confidence: Optional[float] = None
    
    
    @strawberry.type
    class ValidationReportConnection:
        """Paginated validation reports."""
        items: List[ValidationReportType]
        total_count: int
        has_next_page: bool
        has_previous_page: bool
    
    
    @strawberry.type
    class SuccessResponse:
        """Generic success response."""
        success: bool
        message: str
    
    
    @strawberry.type
    class ErrorResponse:
        """Generic error response."""
        success: bool
        error: str
        message: str

else:
    # Stub types when Strawberry not available
    class VerdictEnum:
        pass
    
    class SeverityEnum:
        pass
    
    class PriorityLevelEnum:
        pass
    
    class ValidationResultType:
        pass
    
    class ValidationReportType:
        pass
    
    class UserType:
        pass
    
    class OrganizationType:
        pass
    
    class MetricsType:
        pass
    
    class ValidationStatusUpdate:
        pass
    
    class MetricsUpdate:
        pass
    
    class ValidationReportInput:
        pass
    
    class ValidationReportFilterInput:
        pass
    
    class ValidationReportConnection:
        pass
    
    class SuccessResponse:
        pass
    
    class ErrorResponse:
        pass


# Export types
__all__ = [
    'VerdictEnum',
    'SeverityEnum',
    'PriorityLevelEnum',
    'ValidationResultType',
    'ValidationReportType',
    'UserType',
    'OrganizationType',
    'MetricsType',
    'ValidationStatusUpdate',
    'MetricsUpdate',
    'ValidationReportInput',
    'ValidationReportFilterInput',
    'ValidationReportConnection',
    'SuccessResponse',
    'ErrorResponse'
]

