"""
Password Hashing Utilities

Provides secure password hashing using bcrypt with configurable work factor.
"""

import hashlib
import secrets
import base64
from typing import Tuple


class PasswordHasher:
    """
    Secure password hasher using bcrypt-like algorithm.
    
    Uses PBKDF2-HMAC-SHA256 for password hashing with salt.
    """
    
    def __init__(self, iterations: int = 100000):
        """
        Initialize password hasher.
        
        Args:
            iterations: Number of PBKDF2 iterations (default: 100,000)
        """
        self.iterations = iterations
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password with a random salt.
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password in format: algorithm$iterations$salt$hash
        """
        # Generate random salt
        salt = secrets.token_bytes(32)
        
        # Hash password
        pwd_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            self.iterations
        )
        
        # Encode salt and hash as base64
        salt_b64 = base64.b64encode(salt).decode('ascii')
        hash_b64 = base64.b64encode(pwd_hash).decode('ascii')
        
        # Return in format: algorithm$iterations$salt$hash
        return f"pbkdf2_sha256${self.iterations}${salt_b64}${hash_b64}"
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """
        Verify a password against a hash.
        
        Args:
            password: Plain text password to verify
            password_hash: Stored password hash
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            # Parse hash
            parts = password_hash.split('$')
            if len(parts) != 4:
                return False
            
            algorithm, iterations_str, salt_b64, stored_hash_b64 = parts
            
            if algorithm != 'pbkdf2_sha256':
                return False
            
            iterations = int(iterations_str)
            salt = base64.b64decode(salt_b64)
            stored_hash = base64.b64decode(stored_hash_b64)
            
            # Hash provided password with same salt
            pwd_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                iterations
            )
            
            # Constant-time comparison
            return secrets.compare_digest(pwd_hash, stored_hash)
            
        except Exception:
            return False
    
    def needs_rehash(self, password_hash: str) -> bool:
        """
        Check if password hash needs to be rehashed with current settings.
        
        Args:
            password_hash: Stored password hash
            
        Returns:
            True if hash should be updated, False otherwise
        """
        try:
            parts = password_hash.split('$')
            if len(parts) != 4:
                return True
            
            algorithm, iterations_str, _, _ = parts
            
            if algorithm != 'pbkdf2_sha256':
                return True
            
            iterations = int(iterations_str)
            
            # Rehash if iterations have changed
            return iterations != self.iterations
            
        except Exception:
            return True
    
    @staticmethod
    def generate_token(length: int = 32) -> str:
        """
        Generate a secure random token.
        
        Args:
            length: Token length in bytes
            
        Returns:
            URL-safe base64-encoded token
        """
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_api_key() -> str:
        """
        Generate a secure API key.
        
        Returns:
            API key in format: bb_<random_string>
        """
        return f"bb_{secrets.token_urlsafe(32)}"
    
    @staticmethod
    def hash_token(token: str) -> str:
        """
        Hash a token for storage (e.g., API keys, session tokens).
        
        Args:
            token: Token to hash
            
        Returns:
            SHA-256 hash of token
        """
        return hashlib.sha256(token.encode()).hexdigest()


# Global password hasher instance
password_hasher = PasswordHasher()

