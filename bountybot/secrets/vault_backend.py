"""
HashiCorp Vault backend for secrets management.

Provides integration with HashiCorp Vault for enterprise secrets management.
"""

import os
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime

from .models import Secret, SecretMetadata, SecretVersion, SecretType, SecretAccessLog

logger = logging.getLogger(__name__)

# Try to import hvac (HashiCorp Vault client)
try:
    import hvac
    HVAC_AVAILABLE = True
except ImportError:
    logger.warning("hvac package not installed. Install with: pip install hvac")
    HVAC_AVAILABLE = False
    hvac = None


class VaultBackend:
    """
    HashiCorp Vault backend for secrets management.
    """
    
    def __init__(
        self,
        vault_url: str = None,
        vault_token: str = None,
        vault_namespace: str = None,
        mount_point: str = 'secret'
    ):
        """
        Initialize Vault backend.
        
        Args:
            vault_url: Vault server URL
            vault_token: Vault authentication token
            vault_namespace: Vault namespace
            mount_point: KV secrets engine mount point
        """
        if not HVAC_AVAILABLE:
            logger.warning("Vault backend not available - hvac not installed")
            self.enabled = False
            return
        
        self.enabled = True
        self.vault_url = vault_url or os.getenv('VAULT_ADDR', 'http://localhost:8200')
        self.vault_token = vault_token or os.getenv('VAULT_TOKEN')
        self.vault_namespace = vault_namespace or os.getenv('VAULT_NAMESPACE')
        self.mount_point = mount_point
        
        if not self.vault_token:
            logger.warning("No Vault token provided - Vault backend disabled")
            self.enabled = False
            return
        
        try:
            # Initialize Vault client
            self.client = hvac.Client(
                url=self.vault_url,
                token=self.vault_token,
                namespace=self.vault_namespace
            )
            
            # Verify authentication
            if not self.client.is_authenticated():
                logger.error("Vault authentication failed")
                self.enabled = False
                return
            
            logger.info(f"Connected to Vault at: {self.vault_url}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Vault client: {e}")
            self.enabled = False
    
    def create_secret(
        self,
        secret_id: str,
        value: str,
        secret_type: SecretType = SecretType.GENERIC,
        description: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
        ttl_seconds: Optional[int] = None,
        created_by: Optional[str] = None
    ) -> Optional[Secret]:
        """
        Create a new secret in Vault.
        
        Args:
            secret_id: Unique secret identifier
            value: Secret value
            secret_type: Type of secret
            description: Secret description
            tags: Secret tags
            ttl_seconds: Time to live in seconds
            created_by: User who created the secret
            
        Returns:
            Created secret or None if failed
        """
        if not self.enabled:
            logger.warning("Vault backend not enabled")
            return None
        
        try:
            # Prepare metadata
            now = datetime.utcnow()
            metadata = {
                'secret_type': secret_type.value,
                'description': description,
                'tags': tags or {},
                'ttl_seconds': ttl_seconds,
                'created_by': created_by,
                'created_at': now.isoformat()
            }
            
            # Write secret to Vault
            self.client.secrets.kv.v2.create_or_update_secret(
                path=secret_id,
                secret={'value': value},
                mount_point=self.mount_point,
                cas=0  # Create only if doesn't exist
            )
            
            # Write metadata
            self.client.secrets.kv.v2.update_metadata(
                path=secret_id,
                mount_point=self.mount_point,
                custom_metadata=metadata
            )
            
            logger.info(f"Created secret in Vault: {secret_id}")
            
            # Return secret object
            secret_metadata = SecretMetadata(
                secret_id=secret_id,
                secret_type=secret_type,
                created_at=now,
                updated_at=now,
                created_by=created_by,
                description=description,
                tags=tags or {},
                ttl_seconds=ttl_seconds
            )
            
            return Secret(
                metadata=secret_metadata,
                current_value=value,
                current_version=1,
                versions=[]
            )
            
        except Exception as e:
            logger.error(f"Failed to create secret in Vault: {e}")
            return None
    
    def get_secret(self, secret_id: str, version: Optional[int] = None) -> Optional[Secret]:
        """
        Get a secret from Vault.
        
        Args:
            secret_id: Secret identifier
            version: Specific version to retrieve (latest if None)
            
        Returns:
            Secret or None if not found
        """
        if not self.enabled:
            logger.warning("Vault backend not enabled")
            return None
        
        try:
            # Read secret from Vault
            response = self.client.secrets.kv.v2.read_secret_version(
                path=secret_id,
                version=version,
                mount_point=self.mount_point
            )
            
            if not response or 'data' not in response:
                return None
            
            data = response['data']
            secret_data = data.get('data', {})
            metadata_response = data.get('metadata', {})
            
            # Get custom metadata
            try:
                metadata_info = self.client.secrets.kv.v2.read_secret_metadata(
                    path=secret_id,
                    mount_point=self.mount_point
                )
                custom_metadata = metadata_info.get('data', {}).get('custom_metadata', {})
            except:
                custom_metadata = {}
            
            # Parse metadata
            secret_type = SecretType(custom_metadata.get('secret_type', 'generic'))
            created_at = datetime.fromisoformat(custom_metadata.get('created_at', datetime.utcnow().isoformat()))
            
            metadata = SecretMetadata(
                secret_id=secret_id,
                secret_type=secret_type,
                created_at=created_at,
                updated_at=datetime.fromisoformat(metadata_response.get('created_time', datetime.utcnow().isoformat())),
                created_by=custom_metadata.get('created_by'),
                description=custom_metadata.get('description'),
                tags=custom_metadata.get('tags', {}),
                ttl_seconds=custom_metadata.get('ttl_seconds')
            )
            
            # Create secret
            secret = Secret(
                metadata=metadata,
                current_value=secret_data.get('value', ''),
                current_version=metadata_response.get('version', 1),
                versions=[]
            )
            
            return secret
            
        except Exception as e:
            logger.error(f"Failed to get secret from Vault: {e}")
            return None
    
    def update_secret(
        self,
        secret_id: str,
        new_value: str,
        updated_by: Optional[str] = None
    ) -> Optional[Secret]:
        """
        Update a secret in Vault (creates new version).
        
        Args:
            secret_id: Secret identifier
            new_value: New secret value
            updated_by: User updating the secret
            
        Returns:
            Updated secret or None if failed
        """
        if not self.enabled:
            logger.warning("Vault backend not enabled")
            return None
        
        try:
            # Update secret in Vault
            self.client.secrets.kv.v2.create_or_update_secret(
                path=secret_id,
                secret={'value': new_value},
                mount_point=self.mount_point
            )
            
            logger.info(f"Updated secret in Vault: {secret_id}")
            
            # Return updated secret
            return self.get_secret(secret_id)
            
        except Exception as e:
            logger.error(f"Failed to update secret in Vault: {e}")
            return None
    
    def delete_secret(self, secret_id: str) -> bool:
        """
        Delete a secret from Vault.
        
        Args:
            secret_id: Secret identifier
            
        Returns:
            True if deleted, False if failed
        """
        if not self.enabled:
            logger.warning("Vault backend not enabled")
            return False
        
        try:
            # Delete all versions and metadata
            self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=secret_id,
                mount_point=self.mount_point
            )
            
            logger.info(f"Deleted secret from Vault: {secret_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete secret from Vault: {e}")
            return False
    
    def list_secrets(self) -> List[str]:
        """
        List all secret IDs in Vault.
        
        Returns:
            List of secret IDs
        """
        if not self.enabled:
            logger.warning("Vault backend not enabled")
            return []
        
        try:
            response = self.client.secrets.kv.v2.list_secrets(
                path='',
                mount_point=self.mount_point
            )
            
            if not response or 'data' not in response:
                return []
            
            return response['data'].get('keys', [])
            
        except Exception as e:
            logger.error(f"Failed to list secrets from Vault: {e}")
            return []


__all__ = ['VaultBackend']

