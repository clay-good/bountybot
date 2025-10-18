"""
Tests for secrets management module.
"""

import unittest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime


class TestSecretModels(unittest.TestCase):
    """Test secret models."""
    
    def test_secret_type_enum(self):
        """Test SecretType enum."""
        from bountybot.secrets.models import SecretType
        
        self.assertEqual(SecretType.API_KEY.value, "api_key")
        self.assertEqual(SecretType.PASSWORD.value, "password")
        self.assertEqual(SecretType.TOKEN.value, "token")
    
    def test_secret_version_creation(self):
        """Test SecretVersion creation."""
        from bountybot.secrets.models import SecretVersion
        
        version = SecretVersion(
            version=1,
            value="test_value",
            created_at=datetime.utcnow(),
            created_by="test_user"
        )
        
        self.assertEqual(version.version, 1)
        self.assertEqual(version.value, "test_value")
        self.assertEqual(version.created_by, "test_user")
    
    def test_secret_metadata_creation(self):
        """Test SecretMetadata creation."""
        from bountybot.secrets.models import SecretMetadata, SecretType
        
        now = datetime.utcnow()
        metadata = SecretMetadata(
            secret_id="test_secret",
            secret_type=SecretType.API_KEY,
            created_at=now,
            updated_at=now,
            description="Test secret"
        )
        
        self.assertEqual(metadata.secret_id, "test_secret")
        self.assertEqual(metadata.secret_type, SecretType.API_KEY)
        self.assertEqual(metadata.description, "Test secret")
    
    def test_secret_creation(self):
        """Test Secret creation."""
        from bountybot.secrets.models import Secret, SecretMetadata, SecretType
        
        now = datetime.utcnow()
        metadata = SecretMetadata(
            secret_id="test_secret",
            secret_type=SecretType.API_KEY,
            created_at=now,
            updated_at=now
        )
        
        secret = Secret(
            metadata=metadata,
            current_value="test_value",
            current_version=1
        )
        
        self.assertEqual(secret.current_value, "test_value")
        self.assertEqual(secret.current_version, 1)
    
    def test_secret_is_expired(self):
        """Test secret expiration check."""
        from bountybot.secrets.models import Secret, SecretMetadata, SecretType
        from datetime import timedelta
        
        now = datetime.utcnow()
        
        # Not expired
        metadata = SecretMetadata(
            secret_id="test_secret",
            secret_type=SecretType.API_KEY,
            created_at=now,
            updated_at=now,
            expires_at=now + timedelta(hours=1)
        )
        secret = Secret(metadata=metadata, current_value="test", current_version=1)
        self.assertFalse(secret.is_expired())
        
        # Expired
        metadata.expires_at = now - timedelta(hours=1)
        self.assertTrue(secret.is_expired())


class TestSecretEncryption(unittest.TestCase):
    """Test secret encryption."""
    
    def test_encryption_initialization(self):
        """Test encryption initialization."""
        from bountybot.secrets.encryption import SecretEncryption
        
        encryption = SecretEncryption()
        self.assertIsNotNone(encryption)
    
    def test_encrypt_decrypt(self):
        """Test encryption and decryption."""
        from bountybot.secrets.encryption import SecretEncryption
        
        encryption = SecretEncryption()
        
        if not encryption.enabled:
            self.skipTest("Cryptography not available")
        
        plaintext = "my_secret_value"
        encrypted = encryption.encrypt(plaintext)
        
        self.assertNotEqual(encrypted, plaintext)
        
        decrypted = encryption.decrypt(encrypted)
        self.assertEqual(decrypted, plaintext)
    
    def test_generate_master_key(self):
        """Test master key generation."""
        from bountybot.secrets.encryption import SecretEncryption
        
        key = SecretEncryption.generate_master_key()
        
        if key:
            self.assertIsInstance(key, str)
            self.assertGreater(len(key), 0)


class TestLocalVaultBackend(unittest.TestCase):
    """Test local vault backend."""
    
    def setUp(self):
        """Set up test vault."""
        self.temp_dir = tempfile.mkdtemp()
        self.vault_path = Path(self.temp_dir) / "test_vault"
    
    def tearDown(self):
        """Clean up test vault."""
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    def test_backend_initialization(self):
        """Test backend initialization."""
        from bountybot.secrets.local_backend import LocalVaultBackend
        
        backend = LocalVaultBackend(vault_path=str(self.vault_path))
        self.assertIsNotNone(backend)
        self.assertTrue(self.vault_path.exists())
    
    def test_create_secret(self):
        """Test secret creation."""
        from bountybot.secrets.local_backend import LocalVaultBackend
        from bountybot.secrets.models import SecretType
        
        backend = LocalVaultBackend(vault_path=str(self.vault_path))
        
        secret = backend.create_secret(
            secret_id="test_secret",
            value="test_value",
            secret_type=SecretType.API_KEY,
            description="Test secret"
        )
        
        self.assertIsNotNone(secret)
        self.assertEqual(secret.metadata.secret_id, "test_secret")
        self.assertEqual(secret.current_value, "test_value")
    
    def test_get_secret(self):
        """Test secret retrieval."""
        from bountybot.secrets.local_backend import LocalVaultBackend
        from bountybot.secrets.models import SecretType
        
        backend = LocalVaultBackend(vault_path=str(self.vault_path))
        
        # Create secret
        backend.create_secret(
            secret_id="test_secret",
            value="test_value",
            secret_type=SecretType.API_KEY
        )
        
        # Get secret
        secret = backend.get_secret("test_secret")
        self.assertIsNotNone(secret)
        self.assertEqual(secret.current_value, "test_value")
    
    def test_update_secret(self):
        """Test secret update."""
        from bountybot.secrets.local_backend import LocalVaultBackend
        from bountybot.secrets.models import SecretType
        
        backend = LocalVaultBackend(vault_path=str(self.vault_path))
        
        # Create secret
        backend.create_secret(
            secret_id="test_secret",
            value="old_value",
            secret_type=SecretType.API_KEY
        )
        
        # Update secret
        secret = backend.update_secret("test_secret", "new_value")
        self.assertIsNotNone(secret)
        self.assertEqual(secret.current_value, "new_value")
        self.assertEqual(secret.current_version, 2)
    
    def test_delete_secret(self):
        """Test secret deletion."""
        from bountybot.secrets.local_backend import LocalVaultBackend
        from bountybot.secrets.models import SecretType
        
        backend = LocalVaultBackend(vault_path=str(self.vault_path))
        
        # Create secret
        backend.create_secret(
            secret_id="test_secret",
            value="test_value",
            secret_type=SecretType.API_KEY
        )
        
        # Delete secret
        success = backend.delete_secret("test_secret")
        self.assertTrue(success)
        
        # Verify deleted
        secret = backend.get_secret("test_secret")
        self.assertIsNone(secret)
    
    def test_list_secrets(self):
        """Test listing secrets."""
        from bountybot.secrets.local_backend import LocalVaultBackend
        from bountybot.secrets.models import SecretType
        
        backend = LocalVaultBackend(vault_path=str(self.vault_path))
        
        # Create secrets
        backend.create_secret("secret1", "value1", SecretType.API_KEY)
        backend.create_secret("secret2", "value2", SecretType.TOKEN)
        
        # List secrets
        secrets = backend.list_secrets()
        self.assertEqual(len(secrets), 2)
        self.assertIn("secret1", secrets)
        self.assertIn("secret2", secrets)


class TestVaultBackend(unittest.TestCase):
    """Test Vault backend."""
    
    def test_backend_initialization(self):
        """Test backend initialization."""
        from bountybot.secrets.vault_backend import VaultBackend
        
        backend = VaultBackend()
        self.assertIsNotNone(backend)
        # Backend may not be enabled if Vault not available


class TestSecretsManager(unittest.TestCase):
    """Test secrets manager."""
    
    def setUp(self):
        """Set up test vault."""
        self.temp_dir = tempfile.mkdtemp()
        self.vault_path = Path(self.temp_dir) / "test_vault"
    
    def tearDown(self):
        """Clean up test vault."""
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    def test_manager_initialization(self):
        """Test manager initialization."""
        from bountybot.secrets import SecretsManager
        
        manager = SecretsManager(vault_path=str(self.vault_path))
        self.assertIsNotNone(manager)
    
    def test_create_and_get_secret(self):
        """Test creating and getting secret."""
        from bountybot.secrets import SecretsManager, SecretType
        
        manager = SecretsManager(vault_path=str(self.vault_path))
        
        # Create secret
        secret = manager.create_secret(
            secret_id="test_secret",
            value="test_value",
            secret_type=SecretType.API_KEY
        )
        self.assertIsNotNone(secret)
        
        # Get secret
        value = manager.get_secret("test_secret")
        self.assertEqual(value, "test_value")
    
    def test_get_nonexistent_secret(self):
        """Test getting nonexistent secret."""
        from bountybot.secrets import SecretsManager, SecretNotFoundError
        
        manager = SecretsManager(vault_path=str(self.vault_path))
        
        with self.assertRaises(SecretNotFoundError):
            manager.get_secret("nonexistent")
    
    def test_get_or_create_secret(self):
        """Test get_or_create_secret."""
        from bountybot.secrets import SecretsManager, SecretType
        
        manager = SecretsManager(vault_path=str(self.vault_path))
        
        # First call creates
        value1 = manager.get_or_create_secret(
            "test_secret",
            default_value="default_value",
            secret_type=SecretType.API_KEY
        )
        self.assertEqual(value1, "default_value")
        
        # Second call gets existing
        value2 = manager.get_or_create_secret("test_secret")
        self.assertEqual(value2, "default_value")


class TestSecretsModule(unittest.TestCase):
    """Test secrets module."""
    
    def test_module_imports(self):
        """Test module imports."""
        import bountybot.secrets
        
        self.assertIsNotNone(bountybot.secrets)
    
    def test_module_exports(self):
        """Test module exports."""
        from bountybot.secrets import (
            SecretsManager,
            SecretNotFoundError,
            VaultBackend,
            LocalVaultBackend,
            SecretEncryption
        )
        
        self.assertIsNotNone(SecretsManager)
        self.assertIsNotNone(SecretNotFoundError)
        self.assertIsNotNone(VaultBackend)
        self.assertIsNotNone(LocalVaultBackend)
        self.assertIsNotNone(SecretEncryption)


if __name__ == '__main__':
    unittest.main()

