"""
Database Module

Provides persistent storage for:
- Bug bounty reports
- Validation results
- Priority scores
- Researcher information
- Historical metrics
- Audit logs

Uses SQLAlchemy ORM with PostgreSQL backend.
"""

from .models import (
    Base,
    Report,
    ValidationResult,
    Researcher,
    AuditLog,
    Metric
)

from .session import (
    DatabaseSession,
    get_session,
    init_database,
    session_scope,
    health_check,
    get_database_stats
)

from .repository import (
    ReportRepository,
    ValidationResultRepository,
    ResearcherRepository,
    MetricsRepository,
    AuditLogRepository
)

__all__ = [
    # Models
    'Base',
    'Report',
    'ValidationResult',
    'Researcher',
    'AuditLog',
    'Metric',
    
    # Session management
    'DatabaseSession',
    'get_session',
    'init_database',
    'session_scope',
    'health_check',
    'get_database_stats',
    
    # Repositories
    'ReportRepository',
    'ValidationResultRepository',
    'ResearcherRepository',
    'MetricsRepository',
    'AuditLogRepository'
]

