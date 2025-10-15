"""
Database Session Management

Handles database connections, session lifecycle, and initialization.
"""

import logging
from contextlib import contextmanager
from typing import Generator, Optional
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool

from .models import Base

logger = logging.getLogger(__name__)


class DatabaseSession:
    """
    Database session manager with connection pooling.
    
    Supports both PostgreSQL (production) and SQLite (development/testing).
    """
    
    def __init__(self, database_url: str, echo: bool = False, pool_size: int = 5, max_overflow: int = 10):
        """
        Initialize database session manager.
        
        Args:
            database_url: Database connection URL
                - PostgreSQL: postgresql://user:pass@host:port/dbname
                - SQLite: sqlite:///path/to/db.sqlite
            echo: Whether to log SQL statements
            pool_size: Number of connections to maintain in pool
            max_overflow: Maximum overflow connections beyond pool_size
        """
        self.database_url = database_url
        self.echo = echo
        
        # Determine if using SQLite
        self.is_sqlite = database_url.startswith('sqlite')
        
        # Create engine with appropriate settings
        if self.is_sqlite:
            # SQLite-specific settings
            self.engine = create_engine(
                database_url,
                echo=echo,
                connect_args={'check_same_thread': False}  # Allow multi-threading
            )
            # Enable foreign keys for SQLite
            @event.listens_for(self.engine, "connect")
            def set_sqlite_pragma(dbapi_conn, connection_record):
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()
        else:
            # PostgreSQL with connection pooling
            self.engine = create_engine(
                database_url,
                echo=echo,
                poolclass=QueuePool,
                pool_size=pool_size,
                max_overflow=max_overflow,
                pool_pre_ping=True,  # Verify connections before using
                pool_recycle=3600    # Recycle connections after 1 hour
            )
        
        # Create session factory
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )
        
        logger.info(f"Database session manager initialized: {self._safe_url()}")
    
    def _safe_url(self) -> str:
        """Get database URL with password redacted."""
        url = self.database_url
        if '@' in url and '://' in url:
            # Redact password
            protocol, rest = url.split('://', 1)
            if '@' in rest:
                credentials, host = rest.split('@', 1)
                if ':' in credentials:
                    user, _ = credentials.split(':', 1)
                    return f"{protocol}://{user}:***@{host}"
        return url
    
    def create_all_tables(self):
        """Create all tables in the database."""
        logger.info("Creating database tables...")
        Base.metadata.create_all(bind=self.engine)
        logger.info("Database tables created successfully")
    
    def drop_all_tables(self):
        """Drop all tables in the database. USE WITH CAUTION!"""
        logger.warning("Dropping all database tables...")
        Base.metadata.drop_all(bind=self.engine)
        logger.warning("All database tables dropped")
    
    def get_session(self) -> Session:
        """Get a new database session."""
        return self.SessionLocal()
    
    @contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """
        Provide a transactional scope for database operations.
        
        Usage:
            with db.session_scope() as session:
                session.add(obj)
                # Automatically commits on success, rolls back on error
        """
        session = self.get_session()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database transaction failed: {e}")
            raise
        finally:
            session.close()
    
    def health_check(self) -> bool:
        """
        Check database connectivity.

        Returns:
            True if database is accessible, False otherwise
        """
        try:
            with self.session_scope() as session:
                session.execute(text("SELECT 1"))
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False
    
    def get_stats(self) -> dict:
        """
        Get database connection pool statistics.
        
        Returns:
            Dictionary with pool statistics
        """
        if self.is_sqlite:
            return {
                'database_type': 'sqlite',
                'url': self._safe_url()
            }
        
        pool = self.engine.pool
        return {
            'database_type': 'postgresql',
            'url': self._safe_url(),
            'pool_size': pool.size(),
            'checked_in': pool.checkedin(),
            'checked_out': pool.checkedout(),
            'overflow': pool.overflow(),
            'total_connections': pool.size() + pool.overflow()
        }


# Global database session instance
_db_session: Optional[DatabaseSession] = None


def init_database(database_url: str, echo: bool = False, create_tables: bool = True) -> DatabaseSession:
    """
    Initialize the global database session.
    
    Args:
        database_url: Database connection URL
        echo: Whether to log SQL statements
        create_tables: Whether to create tables if they don't exist
    
    Returns:
        DatabaseSession instance
    """
    global _db_session
    
    _db_session = DatabaseSession(database_url, echo=echo)
    
    if create_tables:
        _db_session.create_all_tables()
    
    return _db_session


def get_session() -> Session:
    """
    Get a database session from the global instance.
    
    Returns:
        SQLAlchemy Session
    
    Raises:
        RuntimeError: If database not initialized
    """
    if _db_session is None:
        raise RuntimeError(
            "Database not initialized. Call init_database() first."
        )
    return _db_session.get_session()


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """
    Provide a transactional scope using the global database instance.
    
    Usage:
        with session_scope() as session:
            session.add(obj)
    """
    if _db_session is None:
        raise RuntimeError(
            "Database not initialized. Call init_database() first."
        )
    
    with _db_session.session_scope() as session:
        yield session


def get_database_stats() -> dict:
    """Get database statistics from global instance."""
    if _db_session is None:
        return {'error': 'Database not initialized'}
    return _db_session.get_stats()


def health_check() -> bool:
    """Check database health using global instance."""
    if _db_session is None:
        return False
    return _db_session.health_check()

