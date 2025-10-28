#!/usr/bin/env python3
"""
Demo script for Secrets Management & Configuration Vault.

Demonstrates:
- Local encrypted vault backend
- HashiCorp Vault integration
- Secret creation, retrieval, update, deletion
- Secret versioning
- Secret rotation
- Encryption at rest
- Audit logging
"""

import sys
import tempfile
from pathlib import Path


def print_header(title: str):
    """Print section header."""
    print()
    print("=" * 80)
    print(f"  {title}")
    print("=" * 80)
    print()


def print_subheader(title: str):
    """Print subsection header."""
    print()
    print(f"📌 {title}")
    print("-" * 80)


def demo_secrets_availability():
    """Demonstrate secrets management availability."""
    print_header("Secrets Management & Configuration Vault - Availability Check")
    
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        print("✓ Cryptography library is available (AES-256-GCM encryption)")
    except ImportError:
        print("⚠️  Cryptography library is not available")
        print("   Install with: pip install cryptography")
        return False
    
    try:
        import hvac
        print("✓ HVAC library is available (HashiCorp Vault client)")
    except ImportError:
        print("⚠️  HVAC library is not available (optional)")
        print("   Install with: pip install hvac")
    
    return True


def demo_encryption():
    """Demonstrate secret encryption."""
    print_header("Secret Encryption (AES-256-GCM)")
    
    from bountybot.secrets.encryption import SecretEncryption
    
    print_subheader("Initialize Encryption")
    encryption = SecretEncryption()
    
    if not encryption.enabled:
        print("⚠️  Encryption not available")
        return
    
    print(f"Encryption enabled: {encryption.enabled}")
    print()
    
    print_subheader("Encrypt Secret")
    plaintext = "my_super_secret_api_key_12345"
    print(f"Plaintext: {plaintext}")
    
    encrypted = encryption.encrypt(plaintext)
    print(f"Encrypted: {encrypted[:50]}...")
    print(f"Length: {len(encrypted)} characters")
    print()
    
    print_subheader("Decrypt Secret")
    decrypted = encryption.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
    print(f"Match: {decrypted == plaintext}")
    print()
    
    print_subheader("Generate Master Key")
    master_key = SecretEncryption.generate_master_key()
    print(f"Master Key: {master_key[:50]}...")
    print("💡 Save this key as BOUNTYBOT_MASTER_KEY environment variable")


def demo_local_vault():
    """Demonstrate local vault backend."""
    print_header("Local Encrypted Vault Backend")
    
    from bountybot.secrets.local_backend import LocalVaultBackend
    from bountybot.secrets.models import SecretType
    
    # Create temporary vault
    temp_dir = tempfile.mkdtemp()
    vault_path = Path(temp_dir) / "demo_vault"
    
    print_subheader("Initialize Local Vault")
    backend = LocalVaultBackend(vault_path=str(vault_path))
    print(f"Vault path: {vault_path}")
    print(f"Secrets path: {backend.secrets_path}")
    print(f"Audit path: {backend.audit_path}")
    print()
    
    print_subheader("Create Secrets")
    
    # Create API key
    secret1 = backend.create_secret(
        secret_id="anthropic_api_key",
        value="sk-ant-api03-xxxxxxxxxxxxx",
        secret_type=SecretType.API_KEY,
        description="Anthropic API key for AI validation",
        tags={"environment": "production", "service": "ai"},
        created_by="admin"
    )
    print(f"✓ Created: {secret1.metadata.secret_id}")
    print(f"  Type: {secret1.metadata.secret_type.value}")
    print(f"  Description: {secret1.metadata.description}")
    print(f"  Version: {secret1.current_version}")
    print()
    
    # Create database password
    secret2 = backend.create_secret(
        secret_id="postgres_password",
        value="super_secure_password_123",
        secret_type=SecretType.PASSWORD,
        description="PostgreSQL database password",
        tags={"environment": "production", "service": "database"},
        ttl_seconds=86400 * 90,  # 90 days
        rotation_enabled=True,
        rotation_interval_days=30,
        created_by="admin"
    )
    print(f"✓ Created: {secret2.metadata.secret_id}")
    print(f"  Type: {secret2.metadata.secret_type.value}")
    print(f"  TTL: {secret2.metadata.ttl_seconds} seconds")
    print(f"  Rotation: {secret2.metadata.rotation_enabled}")
    print()
    
    print_subheader("Retrieve Secrets")
    
    retrieved = backend.get_secret("anthropic_api_key", accessed_by="user1")
    print(f"✓ Retrieved: {retrieved.metadata.secret_id}")
    print(f"  Value: {retrieved.current_value[:20]}...")
    print(f"  Access count: {retrieved.metadata.access_count}")
    print()
    
    print_subheader("Update Secret (Create New Version)")
    
    updated = backend.update_secret(
        "anthropic_api_key",
        "sk-ant-api03-yyyyyyyyyyyy",
        updated_by="admin"
    )
    print(f"✓ Updated: {updated.metadata.secret_id}")
    print(f"  New version: {updated.current_version}")
    print(f"  Total versions: {len(updated.versions)}")
    print()
    
    print_subheader("List Secrets")
    
    secrets = backend.list_secrets()
    print(f"Total secrets: {len(secrets)}")
    for secret_id in secrets:
        print(f"  - {secret_id}")
    print()
    
    print_subheader("Rotate Secret")
    
    rotated = backend.rotate_secret("postgres_password", rotated_by="admin")
    print(f"✓ Rotated: {rotated.metadata.secret_id}")
    print(f"  New value: {rotated.current_value[:20]}...")
    print(f"  Version: {rotated.current_version}")
    print()
    
    print_subheader("Delete Secret")
    
    deleted = backend.delete_secret("anthropic_api_key", deleted_by="admin")
    print(f"✓ Deleted: anthropic_api_key")
    print(f"  Success: {deleted}")
    
    # Cleanup
    import shutil
    shutil.rmtree(temp_dir)


def demo_secrets_manager():
    """Demonstrate secrets manager."""
    print_header("Secrets Manager (Unified Interface)")
    
    from bountybot.secrets import SecretsManager, SecretType, SecretNotFoundError
    
    # Create temporary vault
    temp_dir = tempfile.mkdtemp()
    vault_path = Path(temp_dir) / "demo_vault"
    
    print_subheader("Initialize Secrets Manager")
    manager = SecretsManager(vault_path=str(vault_path))
    print(f"Backend type: {manager.backend_type.value}")
    print()
    
    print_subheader("Create Secrets")
    
    secret = manager.create_secret(
        secret_id="jwt_secret",
        value="my_jwt_secret_key_12345",
        secret_type=SecretType.ENCRYPTION_KEY,
        description="JWT signing key",
        tags={"service": "auth"}
    )
    print(f"✓ Created: {secret.metadata.secret_id}")
    print()
    
    print_subheader("Get Secret Value")
    
    value = manager.get_secret("jwt_secret")
    print(f"Secret value: {value}")
    print()
    
    print_subheader("Get or Create Secret")
    
    # First call creates
    value1 = manager.get_or_create_secret(
        "redis_password",
        default_value="auto_generated_password",
        secret_type=SecretType.PASSWORD
    )
    print(f"First call (created): {value1}")
    
    # Second call retrieves existing
    value2 = manager.get_or_create_secret("redis_password")
    print(f"Second call (retrieved): {value2}")
    print(f"Values match: {value1 == value2}")
    print()
    
    print_subheader("Handle Missing Secret")
    
    try:
        manager.get_secret("nonexistent_secret")
    except SecretNotFoundError as e:
        print(f"✓ Exception raised: {e}")
    
    # Cleanup
    import shutil
    shutil.rmtree(temp_dir)


def demo_vault_integration():
    """Demonstrate HashiCorp Vault integration."""
    print_header("HashiCorp Vault Integration")
    
    from bountybot.secrets.vault_backend import VaultBackend
    
    print_subheader("Initialize Vault Backend")
    
    backend = VaultBackend()
    
    if not backend.enabled:
        print("⚠️  Vault backend not enabled")
        print()
        print("To enable Vault integration:")
        print("  1. Install hvac: pip install hvac")
        print("  2. Start Vault server: vault server -dev")
        print("  3. Set environment variables:")
        print("     export VAULT_ADDR='http://localhost:8200'")
        print("     export VAULT_TOKEN='<your_token>'")
        print()
        print("Vault provides:")
        print("  • Centralized secrets management")
        print("  • Dynamic secret generation")
        print("  • Secret leasing and renewal")
        print("  • Audit logging")
        print("  • High availability")
        print("  • Enterprise-grade security")
    else:
        print(f"✓ Vault backend enabled")
        print(f"  URL: {backend.vault_url}")
        print(f"  Mount point: {backend.mount_point}")


def demo_features():
    """Demonstrate secrets management features."""
    print_header("Secrets Management Features Summary")
    
    features = [
        ("Encryption at Rest", [
            "AES-256-GCM encryption",
            "Master key management",
            "Key derivation with PBKDF2",
            "Secure random nonce generation",
            "Authenticated encryption"
        ]),
        ("Multiple Backends", [
            "HashiCorp Vault (primary)",
            "Local encrypted vault (fallback)",
            "AWS Secrets Manager (planned)",
            "Azure Key Vault (planned)",
            "Automatic backend selection"
        ]),
        ("Secret Lifecycle", [
            "Create, read, update, delete operations",
            "Secret versioning",
            "Automatic secret rotation",
            "TTL and expiration",
            "Secret metadata and tags"
        ]),
        ("Audit & Compliance", [
            "Complete audit trail",
            "Access logging",
            "User attribution",
            "Timestamp tracking",
            "Success/failure logging"
        ]),
        ("Secret Types", [
            "API keys",
            "Passwords",
            "Tokens",
            "Certificates",
            "SSH keys",
            "Database credentials",
            "Encryption keys"
        ]),
        ("Security Features", [
            "Encryption at rest",
            "Access control",
            "Secret expiration",
            "Automatic rotation",
            "Audit logging",
            "Version control"
        ])
    ]
    
    for feature_name, items in features:
        print(f"✅ {feature_name}:")
        for item in items:
            print(f"   • {item}")
        print()


def main():
    """Main demo function."""
    print()
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 78 + "║")
    print("║" + "  🔐 BountyBot Secrets Management & Configuration Vault Demo".center(78) + "║")
    print("║" + " " * 78 + "║")
    print("╚" + "═" * 78 + "╝")
    
    # Check availability
    if not demo_secrets_availability():
        print()
        print("⚠️  Some dependencies are missing. Install them to use secrets management.")
        print()
        return
    
    # Run demos
    demo_encryption()
    demo_local_vault()
    demo_secrets_manager()
    demo_vault_integration()
    demo_features()
    
    # Final message
    print_header("Next Steps")
    print("1. Set up master encryption key:")
    print("   export BOUNTYBOT_MASTER_KEY='<generated_key>'")
    print()
    print("2. Create secrets:")
    print("   from bountybot.secrets import SecretsManager, SecretType")
    print("   manager = SecretsManager()")
    print("   manager.create_secret('api_key', 'value', SecretType.API_KEY)")
    print()
    print("3. Retrieve secrets:")
    print("   value = manager.get_secret('api_key')")
    print()
    print("4. For production, use HashiCorp Vault:")
    print("   export VAULT_ADDR='https://vault.example.com'")
    print("   export VAULT_TOKEN='<your_token>'")
    print()


if __name__ == '__main__':
    main()

