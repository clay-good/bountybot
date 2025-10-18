"""
Redis client with connection pooling and high availability support.
"""

import os
import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class RedisMode(Enum):
    """Redis deployment mode."""
    STANDALONE = "standalone"
    SENTINEL = "sentinel"
    CLUSTER = "cluster"


@dataclass
class RedisConfig:
    """Redis configuration."""
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None
    socket_timeout: float = 5.0
    socket_connect_timeout: float = 5.0
    socket_keepalive: bool = True
    
    # Connection pool settings
    max_connections: int = 50
    connection_pool_kwargs: Optional[Dict[str, Any]] = None
    
    # Sentinel settings (for high availability)
    mode: RedisMode = RedisMode.STANDALONE
    sentinel_hosts: Optional[List[tuple]] = None  # [(host, port), ...]
    sentinel_master_name: Optional[str] = None
    sentinel_password: Optional[str] = None
    
    # Cluster settings (for horizontal scaling)
    cluster_nodes: Optional[List[Dict[str, Any]]] = None  # [{"host": "...", "port": ...}, ...]
    
    # SSL/TLS settings
    ssl: bool = False
    ssl_cert_reqs: Optional[str] = None
    ssl_ca_certs: Optional[str] = None
    
    # Retry settings
    retry_on_timeout: bool = True
    retry_on_error: Optional[List[Exception]] = None
    max_retries: int = 3
    
    # Health check settings
    health_check_interval: int = 30  # seconds
    
    @classmethod
    def from_env(cls) -> 'RedisConfig':
        """Create config from environment variables."""
        return cls(
            host=os.getenv('REDIS_HOST', 'localhost'),
            port=int(os.getenv('REDIS_PORT', '6379')),
            db=int(os.getenv('REDIS_DB', '0')),
            password=os.getenv('REDIS_PASSWORD'),
            max_connections=int(os.getenv('REDIS_MAX_CONNECTIONS', '50')),
            ssl=os.getenv('REDIS_SSL', 'false').lower() == 'true',
            mode=RedisMode(os.getenv('REDIS_MODE', 'standalone'))
        )


class RedisClient:
    """
    Redis client with connection pooling and high availability.
    
    Supports:
    - Standalone Redis
    - Redis Sentinel (high availability)
    - Redis Cluster (horizontal scaling)
    """
    
    def __init__(self, config: Optional[RedisConfig] = None):
        """
        Initialize Redis client.
        
        Args:
            config: Redis configuration (defaults to environment variables)
        """
        self.config = config or RedisConfig.from_env()
        self._client = None
        self._pool = None
        self._connected = False
        
        # Try to import redis
        try:
            import redis
            self.redis = redis
        except ImportError:
            logger.warning("redis package not installed. Install with: pip install redis")
            self.redis = None
    
    def connect(self) -> bool:
        """
        Connect to Redis.
        
        Returns:
            True if connected successfully
        """
        if not self.redis:
            logger.error("Redis package not available")
            return False
        
        try:
            if self.config.mode == RedisMode.STANDALONE:
                self._connect_standalone()
            elif self.config.mode == RedisMode.SENTINEL:
                self._connect_sentinel()
            elif self.config.mode == RedisMode.CLUSTER:
                self._connect_cluster()
            
            # Test connection
            self._client.ping()
            self._connected = True
            logger.info(f"Connected to Redis ({self.config.mode.value})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self._connected = False
            return False
    
    def _connect_standalone(self):
        """Connect to standalone Redis."""
        pool_kwargs = self.config.connection_pool_kwargs or {}
        
        self._pool = self.redis.ConnectionPool(
            host=self.config.host,
            port=self.config.port,
            db=self.config.db,
            password=self.config.password,
            socket_timeout=self.config.socket_timeout,
            socket_connect_timeout=self.config.socket_connect_timeout,
            socket_keepalive=self.config.socket_keepalive,
            max_connections=self.config.max_connections,
            retry_on_timeout=self.config.retry_on_timeout,
            health_check_interval=self.config.health_check_interval,
            ssl=self.config.ssl,
            ssl_cert_reqs=self.config.ssl_cert_reqs,
            ssl_ca_certs=self.config.ssl_ca_certs,
            **pool_kwargs
        )
        
        self._client = self.redis.Redis(connection_pool=self._pool)
    
    def _connect_sentinel(self):
        """Connect to Redis Sentinel for high availability."""
        if not self.config.sentinel_hosts or not self.config.sentinel_master_name:
            raise ValueError("Sentinel mode requires sentinel_hosts and sentinel_master_name")
        
        sentinel = self.redis.Sentinel(
            self.config.sentinel_hosts,
            socket_timeout=self.config.socket_timeout,
            password=self.config.sentinel_password,
            db=self.config.db
        )
        
        self._client = sentinel.master_for(
            self.config.sentinel_master_name,
            socket_timeout=self.config.socket_timeout,
            password=self.config.password,
            db=self.config.db
        )
    
    def _connect_cluster(self):
        """Connect to Redis Cluster for horizontal scaling."""
        if not self.config.cluster_nodes:
            raise ValueError("Cluster mode requires cluster_nodes")
        
        from redis.cluster import RedisCluster
        
        self._client = RedisCluster(
            startup_nodes=self.config.cluster_nodes,
            password=self.config.password,
            socket_timeout=self.config.socket_timeout,
            socket_connect_timeout=self.config.socket_connect_timeout,
            max_connections=self.config.max_connections,
            ssl=self.config.ssl
        )
    
    def disconnect(self):
        """Disconnect from Redis."""
        if self._client:
            try:
                self._client.close()
                logger.info("Disconnected from Redis")
            except Exception as e:
                logger.error(f"Error disconnecting from Redis: {e}")
            finally:
                self._connected = False
                self._client = None
                self._pool = None
    
    def is_connected(self) -> bool:
        """Check if connected to Redis."""
        if not self._connected or not self._client:
            return False
        
        try:
            self._client.ping()
            return True
        except Exception:
            self._connected = False
            return False
    
    def get_client(self):
        """
        Get Redis client.
        
        Returns:
            Redis client instance
        """
        if not self._connected:
            self.connect()
        
        return self._client
    
    def get_info(self) -> Dict[str, Any]:
        """
        Get Redis server information.
        
        Returns:
            Server info dictionary
        """
        if not self.is_connected():
            return {}
        
        try:
            info = self._client.info()
            return {
                'redis_version': info.get('redis_version'),
                'used_memory_human': info.get('used_memory_human'),
                'connected_clients': info.get('connected_clients'),
                'total_commands_processed': info.get('total_commands_processed'),
                'keyspace_hits': info.get('keyspace_hits', 0),
                'keyspace_misses': info.get('keyspace_misses', 0),
                'uptime_in_seconds': info.get('uptime_in_seconds'),
                'mode': self.config.mode.value
            }
        except Exception as e:
            logger.error(f"Failed to get Redis info: {e}")
            return {}
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Statistics dictionary
        """
        info = self.get_info()
        
        hits = info.get('keyspace_hits', 0)
        misses = info.get('keyspace_misses', 0)
        total = hits + misses
        hit_rate = (hits / total * 100) if total > 0 else 0
        
        return {
            'connected': self.is_connected(),
            'mode': self.config.mode.value,
            'redis_version': info.get('redis_version'),
            'used_memory': info.get('used_memory_human'),
            'connected_clients': info.get('connected_clients'),
            'total_commands': info.get('total_commands_processed'),
            'keyspace_hits': hits,
            'keyspace_misses': misses,
            'hit_rate_percent': round(hit_rate, 2),
            'uptime_seconds': info.get('uptime_in_seconds')
        }
    
    def health_check(self) -> bool:
        """
        Perform health check.
        
        Returns:
            True if healthy
        """
        try:
            if not self.is_connected():
                return False
            
            # Test basic operations
            test_key = '__health_check__'
            self._client.set(test_key, '1', ex=1)
            value = self._client.get(test_key)
            self._client.delete(test_key)
            
            return value == b'1'
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False
    
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()

