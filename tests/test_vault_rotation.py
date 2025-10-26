"""
Tests for Vault secret rotation functionality.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from bountybot.secrets.vault_backend import VaultBackend
from bountybot.secrets.models import Secret, SecretMetadata, SecretType


class TestVaultSecretRotation:
    """Test Vault secret rotation."""
    
    @pytest.fixture
    def mock_vault_client(self):
        """Create mock Vault client."""
        client = Mock()
        client.is_authenticated.return_value = True
        client.secrets.kv.v2.read_secret_version.return_value = {
            'data': {
                'data': {'value': 'old-secret-value'},
                'metadata': {
                    'version': 1,
                    'created_time': datetime.utcnow().isoformat()
                }
            }
        }
        client.secrets.kv.v2.read_secret_metadata.return_value = {
            'data': {
                'custom_metadata': {
                    'secret_type': 'api_key',
                    'created_at': datetime.utcnow().isoformat(),
                    'created_by': 'test-user'
                }
            }
        }
        client.secrets.kv.v2.create_or_update_secret.return_value = {
            'data': {'version': 2}
        }
        return client
    
    @pytest.fixture
    def vault_backend(self, mock_vault_client):
        """Create Vault backend with mock client."""
        with patch('bountybot.secrets.vault_backend.hvac') as mock_hvac:
            mock_hvac.Client.return_value = mock_vault_client
            backend = VaultBackend(
                vault_url='http://localhost:8200',
                vault_token='test-token'
            )
            backend.client = mock_vault_client
            backend.enabled = True
            backend.mount_point = 'secret'
            return backend
    
    def test_rotate_api_key(self, vault_backend, mock_vault_client):
        """Test rotating an API key."""
        secret_id = 'test-api-key'
        rotated_by = 'admin'
        
        # Rotate secret
        rotated_secret = vault_backend.rotate_secret(secret_id, rotated_by)
        
        # Verify secret was rotated
        assert rotated_secret is not None
        assert mock_vault_client.secrets.kv.v2.create_or_update_secret.called
        
        # Verify new value was generated (should be 64 hex characters)
        call_args = mock_vault_client.secrets.kv.v2.create_or_update_secret.call_args
        new_value = call_args[1]['secret']['value']
        assert len(new_value) == 64
        assert all(c in '0123456789abcdef' for c in new_value)
    
    def test_rotate_password(self, vault_backend, mock_vault_client):
        """Test rotating a password."""
        # Update mock to return password type
        mock_vault_client.secrets.kv.v2.read_secret_metadata.return_value = {
            'data': {
                'custom_metadata': {
                    'secret_type': 'password',
                    'created_at': datetime.utcnow().isoformat()
                }
            }
        }
        
        secret_id = 'test-password'
        rotated_secret = vault_backend.rotate_secret(secret_id)
        
        # Verify password was rotated
        assert rotated_secret is not None
        
        # Verify new password was generated (should be 32 characters)
        call_args = mock_vault_client.secrets.kv.v2.create_or_update_secret.call_args
        new_value = call_args[1]['secret']['value']
        assert len(new_value) == 32
    
    def test_rotate_token(self, vault_backend, mock_vault_client):
        """Test rotating a token."""
        # Update mock to return token type
        mock_vault_client.secrets.kv.v2.read_secret_metadata.return_value = {
            'data': {
                'custom_metadata': {
                    'secret_type': 'token',
                    'created_at': datetime.utcnow().isoformat()
                }
            }
        }
        
        secret_id = 'test-token'
        rotated_secret = vault_backend.rotate_secret(secret_id)
        
        # Verify token was rotated
        assert rotated_secret is not None
        
        # Verify new token was generated (URL-safe)
        call_args = mock_vault_client.secrets.kv.v2.create_or_update_secret.call_args
        new_value = call_args[1]['secret']['value']
        assert len(new_value) > 0
    
    def test_rotate_encryption_key(self, vault_backend, mock_vault_client):
        """Test rotating an encryption key."""
        # Update mock to return encryption_key type
        mock_vault_client.secrets.kv.v2.read_secret_metadata.return_value = {
            'data': {
                'custom_metadata': {
                    'secret_type': 'encryption_key',
                    'created_at': datetime.utcnow().isoformat()
                }
            }
        }
        
        secret_id = 'test-encryption-key'
        rotated_secret = vault_backend.rotate_secret(secret_id)
        
        # Verify encryption key was rotated
        assert rotated_secret is not None
        
        # Verify new key was generated
        call_args = mock_vault_client.secrets.kv.v2.create_or_update_secret.call_args
        new_value = call_args[1]['secret']['value']
        assert len(new_value) > 0
    
    def test_rotate_generic_secret(self, vault_backend, mock_vault_client):
        """Test rotating a generic secret."""
        # Update mock to return generic type
        mock_vault_client.secrets.kv.v2.read_secret_metadata.return_value = {
            'data': {
                'custom_metadata': {
                    'secret_type': 'generic',
                    'created_at': datetime.utcnow().isoformat()
                }
            }
        }
        
        secret_id = 'test-generic'
        rotated_secret = vault_backend.rotate_secret(secret_id)
        
        # Verify secret was rotated
        assert rotated_secret is not None
    
    def test_rotate_nonexistent_secret(self, vault_backend, mock_vault_client):
        """Test rotating a secret that doesn't exist."""
        # Mock get_secret to return None
        with patch.object(vault_backend, 'get_secret', return_value=None):
            secret_id = 'nonexistent-secret'
            rotated_secret = vault_backend.rotate_secret(secret_id)
            
            # Should return None
            assert rotated_secret is None
    
    def test_rotate_when_disabled(self):
        """Test rotating when Vault backend is disabled."""
        backend = VaultBackend()
        backend.enabled = False
        
        rotated_secret = backend.rotate_secret('test-secret')
        
        # Should return None
        assert rotated_secret is None
    
    def test_rotate_with_error(self, vault_backend, mock_vault_client):
        """Test rotation when an error occurs."""
        # Mock get_secret to raise an exception
        with patch.object(vault_backend, 'get_secret', side_effect=Exception("Test error")):
            secret_id = 'test-secret'
            rotated_secret = vault_backend.rotate_secret(secret_id)
            
            # Should return None
            assert rotated_secret is None


class TestSecretsManagerRotation:
    """Test SecretsManager rotation with Vault backend."""
    
    @pytest.fixture
    def mock_vault_backend(self):
        """Create mock Vault backend."""
        backend = Mock()
        backend.rotate_secret.return_value = Mock(
            metadata=Mock(secret_id='test-secret'),
            current_value='new-value',
            current_version=2
        )
        return backend
    
    def test_secrets_manager_vault_rotation(self, mock_vault_backend):
        """Test SecretsManager rotation with Vault backend."""
        from bountybot.secrets.secrets_manager import SecretsManager, BackendType
        
        manager = SecretsManager()
        manager.backend_type = BackendType.VAULT
        manager.backend = mock_vault_backend
        
        secret = manager.rotate_secret('test-secret', 'admin')
        
        # Verify rotation was called
        assert secret is not None
        mock_vault_backend.rotate_secret.assert_called_once_with('test-secret', 'admin')
    
    def test_secrets_manager_vault_rotation_not_found(self, mock_vault_backend):
        """Test SecretsManager rotation when secret not found."""
        from bountybot.secrets.secrets_manager import SecretsManager, BackendType, SecretNotFoundError
        
        mock_vault_backend.rotate_secret.return_value = None
        
        manager = SecretsManager()
        manager.backend_type = BackendType.VAULT
        manager.backend = mock_vault_backend
        
        with pytest.raises(SecretNotFoundError):
            manager.rotate_secret('nonexistent-secret')


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

