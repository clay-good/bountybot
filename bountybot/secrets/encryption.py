"""
Encryption utilities for secrets management.

Provides AES-256-GCM encryption for secrets at rest.
"""

import os
import base64
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

# Try to import cryptography
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    logger.warning("cryptography package not installed. Install with: pip install cryptography")
    CRYPTOGRAPHY_AVAILABLE = False
    AESGCM = None
    hashes = None
    PBKDF2 = None
    default_backend = None


class SecretEncryption:
    """
    Handles encryption and decryption of secrets using AES-256-GCM.
    """
    
    def __init__(self, master_key: str = None):
        """
        Initialize encryption handler.
        
        Args:
            master_key: Master encryption key (generated if not provided)
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            logger.warning("Cryptography not available - encryption disabled")
            self.enabled = False
            return
        
        self.enabled = True
        
        # Get or generate master key
        if master_key:
            self.master_key = master_key.encode()
        else:
            # Try to get from environment
            env_key = os.getenv('BOUNTYBOT_MASTER_KEY')
            if env_key:
                self.master_key = env_key.encode()
            else:
                # Generate new key
                self.master_key = AESGCM.generate_key(bit_length=256)
                logger.warning("Generated new master key - save BOUNTYBOT_MASTER_KEY environment variable")
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            password: Password to derive key from
            salt: Salt for key derivation
            
        Returns:
            Derived key
        """
        if not self.enabled:
            return b''
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext using AES-256-GCM.
        
        Args:
            plaintext: Text to encrypt
            
        Returns:
            Base64-encoded encrypted data (nonce + ciphertext + tag)
        """
        if not self.enabled:
            logger.warning("Encryption not available - returning plaintext")
            return plaintext
        
        try:
            # Generate random nonce
            nonce = os.urandom(12)
            
            # Create AESGCM cipher
            aesgcm = AESGCM(self.master_key)
            
            # Encrypt
            ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
            
            # Combine nonce + ciphertext and encode
            encrypted_data = nonce + ciphertext
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt encrypted data using AES-256-GCM.
        
        Args:
            encrypted_data: Base64-encoded encrypted data
            
        Returns:
            Decrypted plaintext
        """
        if not self.enabled:
            logger.warning("Encryption not available - returning encrypted data as-is")
            return encrypted_data
        
        try:
            # Decode from base64
            data = base64.b64decode(encrypted_data.encode('utf-8'))
            
            # Extract nonce and ciphertext
            nonce = data[:12]
            ciphertext = data[12:]
            
            # Create AESGCM cipher
            aesgcm = AESGCM(self.master_key)
            
            # Decrypt
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
    
    def rotate_key(self, old_key: str, new_key: str, encrypted_data: str) -> str:
        """
        Re-encrypt data with new key.
        
        Args:
            old_key: Old master key
            new_key: New master key
            encrypted_data: Data encrypted with old key
            
        Returns:
            Data encrypted with new key
        """
        if not self.enabled:
            return encrypted_data
        
        # Decrypt with old key
        old_encryption = SecretEncryption(old_key)
        plaintext = old_encryption.decrypt(encrypted_data)
        
        # Encrypt with new key
        new_encryption = SecretEncryption(new_key)
        return new_encryption.encrypt(plaintext)
    
    @staticmethod
    def generate_master_key() -> str:
        """
        Generate a new master encryption key.
        
        Returns:
            Base64-encoded master key
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            logger.warning("Cryptography not available")
            return ""
        
        key = AESGCM.generate_key(bit_length=256)
        return base64.b64encode(key).decode('utf-8')
    
    @staticmethod
    def generate_salt() -> bytes:
        """
        Generate a random salt for key derivation.
        
        Returns:
            Random salt
        """
        return os.urandom(16)


__all__ = ['SecretEncryption']

