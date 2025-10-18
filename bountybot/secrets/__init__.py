"""
Secrets Management module for BountyBot.

Provides enterprise-grade secrets management with multiple backends:
- HashiCorp Vault integration
- Encrypted local vault (fallback)
- AWS Secrets Manager
- Azure Key Vault
- Secret versioning and rotation
- Audit logging
- Dynamic secret generation
"""

from .secrets_manager import SecretsManager, SecretNotFoundError
from .vault_backend import VaultBackend
from .local_backend import LocalVaultBackend
from .encryption import SecretEncryption
from .models import Secret, SecretMetadata, SecretVersion, SecretType

__all__ = [
    'SecretsManager',
    'SecretNotFoundError',
    'VaultBackend',
    'LocalVaultBackend',
    'SecretEncryption',
    'Secret',
    'SecretMetadata',
    'SecretVersion',
    'SecretType'
]

__version__ = '1.0.0'

