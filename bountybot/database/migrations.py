"""
Database Migration System

Simple migration system for schema changes.
For production, consider using Alembic.
"""

import logging
from datetime import datetime
from typing import List, Callable
from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class Migration:
    """Represents a database migration."""
    
    def __init__(self, version: int, name: str, up: Callable, down: Callable):
        """
        Initialize migration.
        
        Args:
            version: Migration version number (sequential)
            name: Human-readable migration name
            up: Function to apply migration
            down: Function to rollback migration
        """
        self.version = version
        self.name = name
        self.up = up
        self.down = down
    
    def __repr__(self):
        return f"Migration(v{self.version}: {self.name})"


class MigrationManager:
    """Manages database migrations."""
    
    def __init__(self, session: Session):
        self.session = session
        self.migrations: List[Migration] = []
        self._ensure_migration_table()
    
    def _ensure_migration_table(self):
        """Create migration tracking table if it doesn't exist."""
        try:
            self.session.execute(text("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
            self.session.commit()
        except Exception as e:
            logger.error(f"Failed to create migration table: {e}")
            self.session.rollback()
            raise
    
    def register(self, migration: Migration):
        """Register a migration."""
        self.migrations.append(migration)
        self.migrations.sort(key=lambda m: m.version)
    
    def get_current_version(self) -> int:
        """Get current database schema version."""
        try:
            result = self.session.execute(text(
                "SELECT MAX(version) FROM schema_migrations"
            )).scalar()
            return result if result else 0
        except Exception:
            return 0
    
    def get_applied_migrations(self) -> List[int]:
        """Get list of applied migration versions."""
        try:
            result = self.session.execute(text(
                "SELECT version FROM schema_migrations ORDER BY version"
            ))
            return [row[0] for row in result]
        except Exception:
            return []
    
    def migrate(self, target_version: int = None):
        """
        Apply migrations up to target version.
        
        Args:
            target_version: Target version (None = latest)
        """
        current_version = self.get_current_version()
        target = target_version if target_version else max([m.version for m in self.migrations], default=0)
        
        if current_version >= target:
            logger.info(f"Database already at version {current_version}")
            return
        
        logger.info(f"Migrating database from v{current_version} to v{target}")
        
        for migration in self.migrations:
            if migration.version <= current_version:
                continue
            if migration.version > target:
                break
            
            logger.info(f"Applying migration: {migration}")
            try:
                migration.up(self.session)
                self.session.execute(text(
                    "INSERT INTO schema_migrations (version, name) VALUES (:version, :name)"
                ), {"version": migration.version, "name": migration.name})
                self.session.commit()
                logger.info(f"Successfully applied migration v{migration.version}")
            except Exception as e:
                logger.error(f"Failed to apply migration v{migration.version}: {e}")
                self.session.rollback()
                raise
    
    def rollback(self, target_version: int = None):
        """
        Rollback migrations to target version.
        
        Args:
            target_version: Target version (None = rollback one version)
        """
        current_version = self.get_current_version()
        target = target_version if target_version is not None else current_version - 1
        
        if current_version <= target:
            logger.info(f"Database already at version {current_version}")
            return
        
        logger.info(f"Rolling back database from v{current_version} to v{target}")
        
        for migration in reversed(self.migrations):
            if migration.version > current_version:
                continue
            if migration.version <= target:
                break
            
            logger.info(f"Rolling back migration: {migration}")
            try:
                migration.down(self.session)
                self.session.execute(text(
                    "DELETE FROM schema_migrations WHERE version = :version"
                ), {"version": migration.version})
                self.session.commit()
                logger.info(f"Successfully rolled back migration v{migration.version}")
            except Exception as e:
                logger.error(f"Failed to rollback migration v{migration.version}: {e}")
                self.session.rollback()
                raise
    
    def status(self) -> dict:
        """Get migration status."""
        current_version = self.get_current_version()
        applied = self.get_applied_migrations()
        pending = [m for m in self.migrations if m.version not in applied]
        
        return {
            'current_version': current_version,
            'applied_migrations': len(applied),
            'pending_migrations': len(pending),
            'latest_available': max([m.version for m in self.migrations], default=0),
            'pending': [{'version': m.version, 'name': m.name} for m in pending]
        }


# Example migrations (these would be in separate files in production)

def migration_001_initial_schema_up(session: Session):
    """Create initial schema."""
    # This is handled by SQLAlchemy's create_all()
    # Just mark as applied
    pass


def migration_001_initial_schema_down(session: Session):
    """Drop initial schema."""
    # This is handled by SQLAlchemy's drop_all()
    pass


def migration_002_add_indexes_up(session: Session):
    """Add performance indexes."""
    session.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_reports_created_at 
        ON reports(created_at DESC)
    """))
    session.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_validation_results_validated_at 
        ON validation_results(validated_at DESC)
    """))


def migration_002_add_indexes_down(session: Session):
    """Remove performance indexes."""
    session.execute(text("DROP INDEX IF EXISTS idx_reports_created_at"))
    session.execute(text("DROP INDEX IF EXISTS idx_validation_results_validated_at"))


def migration_003_add_researcher_rank_up(session: Session):
    """Add rank calculation for researchers."""
    # Rank is already in the model, this would update existing data
    session.execute(text("""
        UPDATE researchers 
        SET rank = CASE 
            WHEN quality_score >= 80 THEN 'Expert'
            WHEN quality_score >= 60 THEN 'Advanced'
            WHEN quality_score >= 40 THEN 'Intermediate'
            ELSE 'Novice'
        END
        WHERE rank IS NULL
    """))


def migration_003_add_researcher_rank_down(session: Session):
    """Remove rank calculation."""
    session.execute(text("UPDATE researchers SET rank = NULL"))


# Register migrations
def get_migrations() -> List[Migration]:
    """Get all available migrations."""
    return [
        Migration(1, "initial_schema", migration_001_initial_schema_up, migration_001_initial_schema_down),
        Migration(2, "add_indexes", migration_002_add_indexes_up, migration_002_add_indexes_down),
        Migration(3, "add_researcher_rank", migration_003_add_researcher_rank_up, migration_003_add_researcher_rank_down),
    ]


def setup_migrations(session: Session) -> MigrationManager:
    """Setup migration manager with all migrations."""
    manager = MigrationManager(session)
    for migration in get_migrations():
        manager.register(migration)
    return manager

