"""
Health Checking

Monitors system health and component availability.
"""

import logging
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class HealthStatus(str, Enum):
    """Health status levels."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ComponentHealth:
    """Health status of a system component."""
    name: str
    status: HealthStatus
    message: str = ""
    last_check: datetime = field(default_factory=datetime.utcnow)
    response_time_ms: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SystemHealth:
    """Overall system health."""
    status: HealthStatus
    components: Dict[str, ComponentHealth]
    uptime_seconds: float
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def is_healthy(self) -> bool:
        """Check if system is healthy."""
        return self.status == HealthStatus.HEALTHY
    
    def is_degraded(self) -> bool:
        """Check if system is degraded."""
        return self.status == HealthStatus.DEGRADED
    
    def is_unhealthy(self) -> bool:
        """Check if system is unhealthy."""
        return self.status == HealthStatus.UNHEALTHY


class HealthChecker:
    """
    Monitors system health and component availability.
    
    Checks:
    - Database connectivity
    - AI provider availability
    - Disk space
    - Memory usage
    - API responsiveness
    - Integration health
    """
    
    def __init__(self):
        """Initialize health checker."""
        self.start_time = time.time()
        self.component_health: Dict[str, ComponentHealth] = {}
        
        logger.info("Initialized HealthChecker")
    
    def check_database(self) -> ComponentHealth:
        """Check database health."""
        start_time = time.time()
        
        try:
            from bountybot.database import DatabaseSession
            
            # Try to create a session and execute a simple query
            db_session = DatabaseSession()
            db_session.health_check()
            
            response_time = (time.time() - start_time) * 1000
            
            health = ComponentHealth(
                name="database",
                status=HealthStatus.HEALTHY,
                message="Database is operational",
                response_time_ms=response_time
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            
            health = ComponentHealth(
                name="database",
                status=HealthStatus.UNHEALTHY,
                message=f"Database error: {str(e)}",
                response_time_ms=response_time
            )
            
            logger.error(f"Database health check failed: {e}")
        
        self.component_health["database"] = health
        return health
    
    def check_ai_provider(self) -> ComponentHealth:
        """Check AI provider health."""
        start_time = time.time()
        
        try:
            from bountybot.ai_providers import AnthropicProvider
            
            # Simple check - verify we can import and initialize
            # In production, you might want to make a test API call
            provider = AnthropicProvider()
            
            response_time = (time.time() - start_time) * 1000
            
            health = ComponentHealth(
                name="ai_provider",
                status=HealthStatus.HEALTHY,
                message="AI provider is available",
                response_time_ms=response_time
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            
            health = ComponentHealth(
                name="ai_provider",
                status=HealthStatus.UNHEALTHY,
                message=f"AI provider error: {str(e)}",
                response_time_ms=response_time
            )
            
            logger.error(f"AI provider health check failed: {e}")
        
        self.component_health["ai_provider"] = health
        return health
    
    def check_disk_space(self, threshold_percent: float = 90.0) -> ComponentHealth:
        """Check disk space."""
        start_time = time.time()
        
        try:
            import shutil
            
            total, used, free = shutil.disk_usage("/")
            percent_used = (used / total) * 100
            
            response_time = (time.time() - start_time) * 1000
            
            if percent_used >= threshold_percent:
                status = HealthStatus.UNHEALTHY
                message = f"Disk space critical: {percent_used:.1f}% used"
            elif percent_used >= threshold_percent * 0.8:
                status = HealthStatus.DEGRADED
                message = f"Disk space warning: {percent_used:.1f}% used"
            else:
                status = HealthStatus.HEALTHY
                message = f"Disk space OK: {percent_used:.1f}% used"
            
            health = ComponentHealth(
                name="disk_space",
                status=status,
                message=message,
                response_time_ms=response_time,
                metadata={
                    "total_gb": total / (1024**3),
                    "used_gb": used / (1024**3),
                    "free_gb": free / (1024**3),
                    "percent_used": percent_used
                }
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            
            health = ComponentHealth(
                name="disk_space",
                status=HealthStatus.UNKNOWN,
                message=f"Disk check error: {str(e)}",
                response_time_ms=response_time
            )
            
            logger.error(f"Disk space check failed: {e}")
        
        self.component_health["disk_space"] = health
        return health
    
    def check_memory(self, threshold_percent: float = 90.0) -> ComponentHealth:
        """Check memory usage."""
        start_time = time.time()
        
        try:
            import psutil
            
            memory = psutil.virtual_memory()
            percent_used = memory.percent
            
            response_time = (time.time() - start_time) * 1000
            
            if percent_used >= threshold_percent:
                status = HealthStatus.UNHEALTHY
                message = f"Memory critical: {percent_used:.1f}% used"
            elif percent_used >= threshold_percent * 0.8:
                status = HealthStatus.DEGRADED
                message = f"Memory warning: {percent_used:.1f}% used"
            else:
                status = HealthStatus.HEALTHY
                message = f"Memory OK: {percent_used:.1f}% used"
            
            health = ComponentHealth(
                name="memory",
                status=status,
                message=message,
                response_time_ms=response_time,
                metadata={
                    "total_gb": memory.total / (1024**3),
                    "available_gb": memory.available / (1024**3),
                    "used_gb": memory.used / (1024**3),
                    "percent_used": percent_used
                }
            )
            
        except ImportError:
            # psutil not installed
            response_time = (time.time() - start_time) * 1000
            
            health = ComponentHealth(
                name="memory",
                status=HealthStatus.UNKNOWN,
                message="psutil not installed, cannot check memory",
                response_time_ms=response_time
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            
            health = ComponentHealth(
                name="memory",
                status=HealthStatus.UNKNOWN,
                message=f"Memory check error: {str(e)}",
                response_time_ms=response_time
            )
            
            logger.error(f"Memory check failed: {e}")
        
        self.component_health["memory"] = health
        return health
    
    def check_integrations(self) -> ComponentHealth:
        """Check integration health."""
        start_time = time.time()
        
        try:
            from bountybot.integrations import IntegrationManager
            
            # Check if integration manager can be initialized
            manager = IntegrationManager()
            
            response_time = (time.time() - start_time) * 1000
            
            health = ComponentHealth(
                name="integrations",
                status=HealthStatus.HEALTHY,
                message="Integrations available",
                response_time_ms=response_time,
                metadata={
                    "integration_count": len(manager.integrations)
                }
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            
            health = ComponentHealth(
                name="integrations",
                status=HealthStatus.DEGRADED,
                message=f"Integration check warning: {str(e)}",
                response_time_ms=response_time
            )
            
            logger.warning(f"Integration health check warning: {e}")
        
        self.component_health["integrations"] = health
        return health
    
    def check_all(self) -> SystemHealth:
        """Check all components and return overall system health."""
        components = {}
        
        # Check all components
        components["database"] = self.check_database()
        components["ai_provider"] = self.check_ai_provider()
        components["disk_space"] = self.check_disk_space()
        components["memory"] = self.check_memory()
        components["integrations"] = self.check_integrations()
        
        # Determine overall status
        unhealthy_count = sum(1 for c in components.values() if c.status == HealthStatus.UNHEALTHY)
        degraded_count = sum(1 for c in components.values() if c.status == HealthStatus.DEGRADED)
        
        if unhealthy_count > 0:
            overall_status = HealthStatus.UNHEALTHY
        elif degraded_count > 0:
            overall_status = HealthStatus.DEGRADED
        else:
            overall_status = HealthStatus.HEALTHY
        
        uptime = time.time() - self.start_time
        
        return SystemHealth(
            status=overall_status,
            components=components,
            uptime_seconds=uptime
        )
    
    def get_component_health(self, component_name: str) -> Optional[ComponentHealth]:
        """Get health status of a specific component."""
        return self.component_health.get(component_name)
    
    def is_healthy(self) -> bool:
        """Check if system is healthy."""
        health = self.check_all()
        return health.is_healthy()


# Global health checker instance
health_checker = HealthChecker()

