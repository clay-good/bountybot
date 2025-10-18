"""
Secrets Manager for BountyBot.

Provides unified interface for secrets management with multiple backends.
"""

import os
import logging
from typing import Optional, Dict, Any, List
from enum import Enum

from .models import Secret, SecretType
from .vault_backend import VaultBackend
from .local_backend import LocalVaultBackend

logger = logging.getLogger(__name__)


class SecretNotFoundError(Exception):
    """Exception raised when secret is not found."""
    pass


class BackendType(Enum):
    """Secret backend type."""
    VAULT = "vault"
    LOCAL = "local"
    AWS_SECRETS_MANAGER = "aws"
    AZURE_KEY_VAULT = "azure"


class SecretsManager:
    """
    Unified secrets manager with multiple backend support.
    
    Automatically selects best available backend:
    1. HashiCorp Vault (if configured)
    2. Local encrypted vault (fallback)
    """
    
    def __init__(
        self,
        backend_type: Optional[BackendType] = None,
        vault_url: Optional[str] = None,
        vault_token: Optional[str] = None,
        vault_path: Optional[str] = None,
        master_key: Optional[str] = None
    ):
        """
        Initialize secrets manager.
        
        Args:
            backend_type: Preferred backend type
            vault_url: Vault server URL
            vault_token: Vault authentication token
            vault_path: Local vault path
            master_key: Master encryption key for local vault
        """
        self.backend_type = backend_type
        self.backend = None
        
        # Try to initialize backends in order of preference
        if backend_type == BackendType.VAULT or backend_type is None:
            vault_backend = VaultBackend(
                vault_url=vault_url,
                vault_token=vault_token
            )
            
            if vault_backend.enabled:
                self.backend = vault_backend
                self.backend_type = BackendType.VAULT
                logger.info("Using HashiCorp Vault backend")
        
        # Fallback to local vault
        if self.backend is None:
            self.backend = LocalVaultBackend(
                vault_path=vault_path,
                master_key=master_key
            )
            self.backend_type = BackendType.LOCAL
            logger.info("Using local encrypted vault backend")
    
    def create_secret(
        self,
        secret_id: str,
        value: str,
        secret_type: SecretType = SecretType.GENERIC,
        description: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
        ttl_seconds: Optional[int] = None,
        rotation_enabled: bool = False,
        rotation_interval_days: Optional[int] = None,
        created_by: Optional[str] = None
    ) -> Secret:
        """
        Create a new secret.
        
        Args:
            secret_id: Unique secret identifier
            value: Secret value
            secret_type: Type of secret
            description: Secret description
            tags: Secret tags
            ttl_seconds: Time to live in seconds
            rotation_enabled: Enable automatic rotation
            rotation_interval_days: Rotation interval in days
            created_by: User who created the secret
            
        Returns:
            Created secret
            
        Raises:
            ValueError: If secret already exists
        """
        if self.backend_type == BackendType.VAULT:
            secret = self.backend.create_secret(
                secret_id=secret_id,
                value=value,
                secret_type=secret_type,
                description=description,
                tags=tags,
                ttl_seconds=ttl_seconds,
                created_by=created_by
            )
        else:
            secret = self.backend.create_secret(
                secret_id=secret_id,
                value=value,
                secret_type=secret_type,
                description=description,
                tags=tags,
                ttl_seconds=ttl_seconds,
                rotation_enabled=rotation_enabled,
                rotation_interval_days=rotation_interval_days,
                created_by=created_by
            )
        
        if not secret:
            raise ValueError(f"Failed to create secret: {secret_id}")
        
        return secret
    
    def get_secret(
        self,
        secret_id: str,
        accessed_by: Optional[str] = None
    ) -> str:
        """
        Get a secret value by ID.
        
        Args:
            secret_id: Secret identifier
            accessed_by: User accessing the secret
            
        Returns:
            Secret value
            
        Raises:
            SecretNotFoundError: If secret not found
        """
        if self.backend_type == BackendType.VAULT:
            secret = self.backend.get_secret(secret_id)
        else:
            secret = self.backend.get_secret(secret_id, accessed_by)
        
        if not secret:
            raise SecretNotFoundError(f"Secret not found: {secret_id}")
        
        # Check if expired
        if secret.is_expired():
            raise SecretNotFoundError(f"Secret expired: {secret_id}")
        
        return secret.current_value
    
    def get_secret_metadata(
        self,
        secret_id: str,
        accessed_by: Optional[str] = None
    ) -> Optional[Secret]:
        """
        Get secret with metadata (without logging access).
        
        Args:
            secret_id: Secret identifier
            accessed_by: User accessing the secret
            
        Returns:
            Secret object or None
        """
        if self.backend_type == BackendType.VAULT:
            return self.backend.get_secret(secret_id)
        else:
            return self.backend.get_secret(secret_id, accessed_by)
    
    def update_secret(
        self,
        secret_id: str,
        new_value: str,
        updated_by: Optional[str] = None
    ) -> Secret:
        """
        Update a secret with a new value.
        
        Args:
            secret_id: Secret identifier
            new_value: New secret value
            updated_by: User updating the secret
            
        Returns:
            Updated secret
            
        Raises:
            SecretNotFoundError: If secret not found
        """
        secret = self.backend.update_secret(secret_id, new_value, updated_by)
        
        if not secret:
            raise SecretNotFoundError(f"Secret not found: {secret_id}")
        
        return secret
    
    def delete_secret(
        self,
        secret_id: str,
        deleted_by: Optional[str] = None
    ) -> bool:
        """
        Delete a secret.
        
        Args:
            secret_id: Secret identifier
            deleted_by: User deleting the secret
            
        Returns:
            True if deleted
            
        Raises:
            SecretNotFoundError: If secret not found
        """
        if self.backend_type == BackendType.VAULT:
            success = self.backend.delete_secret(secret_id)
        else:
            success = self.backend.delete_secret(secret_id, deleted_by)
        
        if not success:
            raise SecretNotFoundError(f"Secret not found: {secret_id}")
        
        return True
    
    def list_secrets(self) -> List[str]:
        """
        List all secret IDs.
        
        Returns:
            List of secret IDs
        """
        return self.backend.list_secrets()
    
    def rotate_secret(
        self,
        secret_id: str,
        rotated_by: Optional[str] = None
    ) -> Secret:
        """
        Rotate a secret (generate new value).
        
        Args:
            secret_id: Secret identifier
            rotated_by: User rotating the secret
            
        Returns:
            Rotated secret
            
        Raises:
            SecretNotFoundError: If secret not found
        """
        if self.backend_type == BackendType.LOCAL:
            secret = self.backend.rotate_secret(secret_id, rotated_by)
            if not secret:
                raise SecretNotFoundError(f"Secret not found: {secret_id}")
            return secret
        else:
            raise NotImplementedError("Secret rotation not implemented for Vault backend")
    
    def get_or_create_secret(
        self,
        secret_id: str,
        default_value: Optional[str] = None,
        secret_type: SecretType = SecretType.GENERIC,
        **kwargs
    ) -> str:
        """
        Get secret or create if doesn't exist.
        
        Args:
            secret_id: Secret identifier
            default_value: Default value if creating
            secret_type: Type of secret
            **kwargs: Additional arguments for create_secret
            
        Returns:
            Secret value
        """
        try:
            return self.get_secret(secret_id)
        except SecretNotFoundError:
            # Generate default value if not provided
            if default_value is None:
                import secrets
                default_value = secrets.token_urlsafe(32)
            
            secret = self.create_secret(
                secret_id=secret_id,
                value=default_value,
                secret_type=secret_type,
                **kwargs
            )
            return secret.current_value


__all__ = ['SecretsManager', 'SecretNotFoundError', 'BackendType']

