import hashlib
import secrets
import time
from typing import Optional, Dict
from datetime import datetime, timedelta
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import logging

logger = logging.getLogger(__name__)

# Security scheme
security = HTTPBearer()


class APIKey:
    """API key model."""
    
    def __init__(
        self,
        key_id: str,
        name: str,
        key_hash: str,
        rate_limit: int = 60,
        created_at: Optional[datetime] = None,
        expires_at: Optional[datetime] = None,
        is_active: bool = True
    ):
        self.key_id = key_id
        self.name = name
        self.key_hash = key_hash
        self.rate_limit = rate_limit
        self.created_at = created_at or datetime.utcnow()
        self.expires_at = expires_at
        self.is_active = is_active
        self.last_used = None
        self.request_count = 0
    
    def is_valid(self) -> bool:
        """Check if API key is valid."""
        if not self.is_active:
            return False
        
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        
        return True
    
    def verify_key(self, key: str) -> bool:
        """Verify API key."""
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return key_hash == self.key_hash
    
    def record_usage(self):
        """Record API key usage."""
        self.last_used = datetime.utcnow()
        self.request_count += 1


class APIKeyAuth:
    """API key authentication manager."""
    
    def __init__(self):
        self.keys: Dict[str, APIKey] = {}
        self._load_default_keys()
    
    def _load_default_keys(self):
        """Load default API keys from environment."""
        import os
        
        # Load from environment variable
        default_key = os.getenv('BOUNTYBOT_API_KEY')
        if default_key:
            key_hash = hashlib.sha256(default_key.encode()).hexdigest()
            api_key = APIKey(
                key_id='default',
                name='Default API Key',
                key_hash=key_hash,
                rate_limit=100
            )
            self.keys['default'] = api_key
            logger.info("Loaded default API key from environment")
    
    def create_key(
        self,
        name: str,
        description: Optional[str] = None,
        rate_limit: int = 60,
        expires_at: Optional[datetime] = None
    ) -> tuple[str, APIKey]:
        """
        Create a new API key.
        
        Returns:
            Tuple of (raw_key, api_key_object)
        """
        # Generate secure random key
        raw_key = f"bb_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        
        # Create API key object
        key_id = f"key_{secrets.token_hex(8)}"
        api_key = APIKey(
            key_id=key_id,
            name=name,
            key_hash=key_hash,
            rate_limit=rate_limit,
            expires_at=expires_at
        )
        
        # Store key
        self.keys[key_id] = api_key
        
        logger.info(f"Created API key: {key_id} ({name})")
        
        return raw_key, api_key
    
    def verify_key(self, raw_key: str) -> Optional[APIKey]:
        """
        Verify API key and return APIKey object if valid.
        
        Args:
            raw_key: Raw API key string
            
        Returns:
            APIKey object if valid, None otherwise
        """
        # Check all keys
        for api_key in self.keys.values():
            if api_key.verify_key(raw_key) and api_key.is_valid():
                api_key.record_usage()
                return api_key
        
        return None
    
    def revoke_key(self, key_id: str) -> bool:
        """
        Revoke an API key.
        
        Args:
            key_id: API key identifier
            
        Returns:
            True if revoked, False if not found
        """
        if key_id in self.keys:
            self.keys[key_id].is_active = False
            logger.info(f"Revoked API key: {key_id}")
            return True
        
        return False
    
    def get_key(self, key_id: str) -> Optional[APIKey]:
        """Get API key by ID."""
        return self.keys.get(key_id)
    
    def list_keys(self) -> list[APIKey]:
        """List all API keys."""
        return list(self.keys.values())


# Global API key manager
api_key_manager = APIKeyAuth()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> APIKey:
    """
    Dependency to get current authenticated user.
    
    Args:
        credentials: HTTP authorization credentials
        
    Returns:
        APIKey object
        
    Raises:
        HTTPException: If authentication fails
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Extract token
    token = credentials.credentials
    
    # Verify token
    api_key = api_key_manager.verify_key(token)
    
    if not api_key:
        logger.warning(f"Invalid API key attempt")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return api_key


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security)
) -> Optional[APIKey]:
    """
    Optional authentication dependency.
    
    Returns:
        APIKey object if authenticated, None otherwise
    """
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials)
    except HTTPException:
        return None


def require_admin(api_key: APIKey = Security(get_current_user)) -> APIKey:
    """
    Dependency to require admin privileges.
    
    Args:
        api_key: Authenticated API key
        
    Returns:
        APIKey object
        
    Raises:
        HTTPException: If not admin
    """
    # Check if key has admin privileges
    # For now, only 'default' key is admin
    if api_key.key_id != 'default':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    
    return api_key


class RateLimitExceeded(Exception):
    """Rate limit exceeded exception."""
    pass


def check_rate_limit(api_key: APIKey, rate_limiter) -> bool:
    """
    Check if request is within rate limit.
    
    Args:
        api_key: API key to check
        rate_limiter: Rate limiter instance
        
    Returns:
        True if within limit
        
    Raises:
        RateLimitExceeded: If rate limit exceeded
    """
    key = f"api_key:{api_key.key_id}"
    
    if not rate_limiter.allow_request(key, api_key.rate_limit):
        raise RateLimitExceeded(
            f"Rate limit exceeded: {api_key.rate_limit} requests per minute"
        )
    
    return True

