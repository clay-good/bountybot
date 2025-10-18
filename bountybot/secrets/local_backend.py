"""
Local encrypted vault backend for secrets management.

Provides encrypted file-based storage as fallback when Vault is not available.
"""

import os
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List
from threading import Lock

from .models import Secret, SecretMetadata, SecretVersion, SecretType, SecretAccessLog
from .encryption import SecretEncryption

logger = logging.getLogger(__name__)


class LocalVaultBackend:
    """
    Local encrypted vault backend.
    
    Stores secrets in encrypted JSON files on disk.
    """
    
    def __init__(self, vault_path: str = None, master_key: str = None):
        """
        Initialize local vault backend.
        
        Args:
            vault_path: Path to vault directory
            master_key: Master encryption key
        """
        self.vault_path = Path(vault_path or os.getenv('BOUNTYBOT_VAULT_PATH', '.bountybot_vault'))
        self.vault_path.mkdir(parents=True, exist_ok=True)
        
        self.secrets_path = self.vault_path / 'secrets'
        self.secrets_path.mkdir(exist_ok=True)
        
        self.audit_path = self.vault_path / 'audit'
        self.audit_path.mkdir(exist_ok=True)
        
        self.encryption = SecretEncryption(master_key)
        self.lock = Lock()
        
        logger.info(f"Initialized local vault at: {self.vault_path}")
    
    def _get_secret_file(self, secret_id: str) -> Path:
        """Get path to secret file."""
        return self.secrets_path / f"{secret_id}.json"
    
    def _log_access(self, log: SecretAccessLog):
        """Log secret access to audit log."""
        try:
            log_file = self.audit_path / f"{datetime.utcnow().strftime('%Y-%m-%d')}.jsonl"
            with open(log_file, 'a') as f:
                f.write(json.dumps(log.to_dict()) + '\n')
        except Exception as e:
            logger.error(f"Failed to log access: {e}")
    
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
        """
        with self.lock:
            secret_file = self._get_secret_file(secret_id)
            
            if secret_file.exists():
                raise ValueError(f"Secret already exists: {secret_id}")
            
            # Create metadata
            now = datetime.utcnow()
            expires_at = None
            if ttl_seconds:
                from datetime import timedelta
                expires_at = now + timedelta(seconds=ttl_seconds)
            
            metadata = SecretMetadata(
                secret_id=secret_id,
                secret_type=secret_type,
                created_at=now,
                updated_at=now,
                created_by=created_by,
                description=description,
                tags=tags or {},
                ttl_seconds=ttl_seconds,
                expires_at=expires_at,
                rotation_enabled=rotation_enabled,
                rotation_interval_days=rotation_interval_days
            )
            
            # Encrypt value
            encrypted_value = self.encryption.encrypt(value)
            
            # Create version
            version = SecretVersion(
                version=1,
                value=encrypted_value,
                created_at=now,
                created_by=created_by
            )
            
            # Create secret
            secret = Secret(
                metadata=metadata,
                current_value=value,
                current_version=1,
                versions=[version]
            )
            
            # Save to file
            data = {
                'metadata': metadata.to_dict(),
                'current_version': 1,
                'versions': [v.to_dict() for v in secret.versions]
            }
            
            with open(secret_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Log access
            self._log_access(SecretAccessLog(
                secret_id=secret_id,
                accessed_at=now,
                accessed_by=created_by,
                access_type='create',
                success=True
            ))
            
            logger.info(f"Created secret: {secret_id}")
            return secret
    
    def get_secret(self, secret_id: str, accessed_by: Optional[str] = None) -> Optional[Secret]:
        """
        Get a secret by ID.
        
        Args:
            secret_id: Secret identifier
            accessed_by: User accessing the secret
            
        Returns:
            Secret or None if not found
        """
        with self.lock:
            secret_file = self._get_secret_file(secret_id)
            
            if not secret_file.exists():
                self._log_access(SecretAccessLog(
                    secret_id=secret_id,
                    accessed_at=datetime.utcnow(),
                    accessed_by=accessed_by,
                    access_type='read',
                    success=False,
                    error_message='Secret not found'
                ))
                return None
            
            try:
                # Load from file
                with open(secret_file, 'r') as f:
                    data = json.load(f)
                
                # Parse metadata
                metadata_dict = data['metadata']
                metadata = SecretMetadata(
                    secret_id=metadata_dict['secret_id'],
                    secret_type=SecretType(metadata_dict['secret_type']),
                    created_at=datetime.fromisoformat(metadata_dict['created_at']),
                    updated_at=datetime.fromisoformat(metadata_dict['updated_at']),
                    created_by=metadata_dict.get('created_by'),
                    updated_by=metadata_dict.get('updated_by'),
                    description=metadata_dict.get('description'),
                    tags=metadata_dict.get('tags', {}),
                    ttl_seconds=metadata_dict.get('ttl_seconds'),
                    expires_at=datetime.fromisoformat(metadata_dict['expires_at']) if metadata_dict.get('expires_at') else None,
                    rotation_enabled=metadata_dict.get('rotation_enabled', False),
                    rotation_interval_days=metadata_dict.get('rotation_interval_days'),
                    last_rotated_at=datetime.fromisoformat(metadata_dict['last_rotated_at']) if metadata_dict.get('last_rotated_at') else None,
                    access_count=metadata_dict.get('access_count', 0),
                    last_accessed_at=datetime.fromisoformat(metadata_dict['last_accessed_at']) if metadata_dict.get('last_accessed_at') else None
                )
                
                # Parse versions
                versions = []
                for v_dict in data['versions']:
                    version = SecretVersion(
                        version=v_dict['version'],
                        value=v_dict['value'],
                        created_at=datetime.fromisoformat(v_dict['created_at']),
                        created_by=v_dict.get('created_by'),
                        metadata=v_dict.get('metadata', {})
                    )
                    versions.append(version)
                
                # Get current version
                current_version = data['current_version']
                current_version_obj = next((v for v in versions if v.version == current_version), versions[-1])
                
                # Decrypt current value
                current_value = self.encryption.decrypt(current_version_obj.value)
                
                # Create secret
                secret = Secret(
                    metadata=metadata,
                    current_value=current_value,
                    current_version=current_version,
                    versions=versions
                )
                
                # Update access metadata
                metadata.access_count += 1
                metadata.last_accessed_at = datetime.utcnow()
                
                # Save updated metadata
                data['metadata'] = metadata.to_dict()
                with open(secret_file, 'w') as f:
                    json.dump(data, f, indent=2)
                
                # Log access
                self._log_access(SecretAccessLog(
                    secret_id=secret_id,
                    accessed_at=datetime.utcnow(),
                    accessed_by=accessed_by,
                    access_type='read',
                    success=True
                ))
                
                return secret
                
            except Exception as e:
                logger.error(f"Failed to get secret {secret_id}: {e}")
                self._log_access(SecretAccessLog(
                    secret_id=secret_id,
                    accessed_at=datetime.utcnow(),
                    accessed_by=accessed_by,
                    access_type='read',
                    success=False,
                    error_message=str(e)
                ))
                return None


    def update_secret(
        self,
        secret_id: str,
        new_value: str,
        updated_by: Optional[str] = None
    ) -> Optional[Secret]:
        """
        Update a secret with a new value (creates new version).

        Args:
            secret_id: Secret identifier
            new_value: New secret value
            updated_by: User updating the secret

        Returns:
            Updated secret or None if not found
        """
        secret = self.get_secret(secret_id)
        if not secret:
            return None

        with self.lock:
            # Encrypt new value
            encrypted_value = self.encryption.encrypt(new_value)

            # Create new version
            new_version_num = secret.current_version + 1
            new_version = SecretVersion(
                version=new_version_num,
                value=encrypted_value,
                created_at=datetime.utcnow(),
                created_by=updated_by
            )

            secret.versions.append(new_version)
            secret.current_version = new_version_num
            secret.current_value = new_value
            secret.metadata.updated_at = datetime.utcnow()
            secret.metadata.updated_by = updated_by

            # Save to file
            secret_file = self._get_secret_file(secret_id)
            data = {
                'metadata': secret.metadata.to_dict(),
                'current_version': secret.current_version,
                'versions': [v.to_dict() for v in secret.versions]
            }

            with open(secret_file, 'w') as f:
                json.dump(data, f, indent=2)

            # Log access
            self._log_access(SecretAccessLog(
                secret_id=secret_id,
                accessed_at=datetime.utcnow(),
                accessed_by=updated_by,
                access_type='update',
                success=True
            ))

            return secret

    def delete_secret(self, secret_id: str, deleted_by: Optional[str] = None) -> bool:
        """
        Delete a secret.

        Args:
            secret_id: Secret identifier
            deleted_by: User deleting the secret

        Returns:
            True if deleted, False if not found
        """
        with self.lock:
            secret_file = self._get_secret_file(secret_id)

            if not secret_file.exists():
                return False

            secret_file.unlink()

            # Log access
            self._log_access(SecretAccessLog(
                secret_id=secret_id,
                accessed_at=datetime.utcnow(),
                accessed_by=deleted_by,
                access_type='delete',
                success=True
            ))

            logger.info(f"Deleted secret: {secret_id}")
            return True

    def list_secrets(self) -> List[str]:
        """
        List all secret IDs.

        Returns:
            List of secret IDs
        """
        with self.lock:
            return [f.stem for f in self.secrets_path.glob('*.json')]

    def rotate_secret(self, secret_id: str, rotated_by: Optional[str] = None) -> Optional[Secret]:
        """
        Rotate a secret (generate new value).

        Args:
            secret_id: Secret identifier
            rotated_by: User rotating the secret

        Returns:
            Rotated secret or None if not found
        """
        secret = self.get_secret(secret_id)
        if not secret:
            return None

        # Generate new value based on secret type
        import secrets as py_secrets

        if secret.metadata.secret_type == SecretType.API_KEY:
            new_value = f"bb_{py_secrets.token_urlsafe(32)}"
        elif secret.metadata.secret_type == SecretType.TOKEN:
            new_value = py_secrets.token_urlsafe(32)
        elif secret.metadata.secret_type == SecretType.PASSWORD:
            new_value = py_secrets.token_urlsafe(24)
        else:
            new_value = py_secrets.token_urlsafe(32)

        # Update secret
        secret = self.update_secret(secret_id, new_value, rotated_by)

        if secret:
            secret.metadata.last_rotated_at = datetime.utcnow()

            # Log rotation
            self._log_access(SecretAccessLog(
                secret_id=secret_id,
                accessed_at=datetime.utcnow(),
                accessed_by=rotated_by,
                access_type='rotate',
                success=True
            ))

        return secret


__all__ = ['LocalVaultBackend']

