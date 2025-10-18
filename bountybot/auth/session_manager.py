"""
Session Management

Handles user session creation, validation, and JWT token generation.
"""

import jwt
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import logging

from .models import Session, User
from .password_hasher import PasswordHasher

logger = logging.getLogger(__name__)


class SessionManager:
    """
    Manages user sessions and JWT tokens.
    """
    
    def __init__(self, secret_key: Optional[str] = None, token_expiry_hours: int = 24):
        """
        Initialize session manager.
        
        Args:
            secret_key: Secret key for JWT signing (generated if not provided)
            token_expiry_hours: Token expiration time in hours
        """
        self.secret_key = secret_key or secrets.token_urlsafe(64)
        self.token_expiry_hours = token_expiry_hours
        self.sessions: Dict[str, Session] = {}
        self.user_sessions: Dict[str, list[str]] = {}  # user_id -> [session_ids]
        self.password_hasher = PasswordHasher()
    
    def create_session(
        self,
        user: User,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Session:
        """
        Create a new session for a user.
        
        Args:
            user: User object
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            Session object with JWT token
        """
        # Generate session ID
        session_id = f"sess_{secrets.token_urlsafe(16)}"
        
        # Generate JWT token
        token = self._generate_jwt_token(user, session_id)
        
        # Generate refresh token
        refresh_token = self.password_hasher.generate_token(32)
        
        # Create session
        session = Session(
            session_id=session_id,
            user_id=user.user_id,
            token=token,
            refresh_token=refresh_token,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=datetime.utcnow() + timedelta(hours=self.token_expiry_hours)
        )
        
        # Store session
        self.sessions[session_id] = session
        
        # Track user sessions
        if user.user_id not in self.user_sessions:
            self.user_sessions[user.user_id] = []
        self.user_sessions[user.user_id].append(session_id)
        
        logger.info(f"Created session {session_id} for user {user.user_id}")
        
        return session
    
    def _generate_jwt_token(self, user: User, session_id: str) -> str:
        """
        Generate JWT token for user.
        
        Args:
            user: User object
            session_id: Session ID
            
        Returns:
            JWT token string
        """
        payload = {
            'user_id': user.user_id,
            'username': user.username,
            'email': user.email,
            'org_id': user.org_id,
            'roles': list(user.roles),
            'session_id': session_id,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=self.token_expiry_hours)
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm='HS256')
        return token
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode JWT token.
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded token payload if valid, None otherwise
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            
            # Check if session is still valid
            session_id = payload.get('session_id')
            if session_id and session_id in self.sessions:
                session = self.sessions[session_id]
                if not session.is_valid():
                    logger.warning(f"Session {session_id} is no longer valid")
                    return None
                
                # Update last activity
                session.last_activity = datetime.utcnow()
            
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """
        Get session by ID.
        
        Args:
            session_id: Session ID
            
        Returns:
            Session object if found and valid, None otherwise
        """
        session = self.sessions.get(session_id)
        if session and session.is_valid():
            return session
        return None
    
    def revoke_session(self, session_id: str) -> bool:
        """
        Revoke a session.
        
        Args:
            session_id: Session ID to revoke
            
        Returns:
            True if revoked, False if not found
        """
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session.revoke()
            
            # Remove from user sessions
            if session.user_id in self.user_sessions:
                self.user_sessions[session.user_id] = [
                    sid for sid in self.user_sessions[session.user_id]
                    if sid != session_id
                ]
            
            logger.info(f"Revoked session {session_id}")
            return True
        
        return False
    
    def revoke_all_user_sessions(self, user_id: str) -> int:
        """
        Revoke all sessions for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            Number of sessions revoked
        """
        if user_id not in self.user_sessions:
            return 0
        
        session_ids = self.user_sessions[user_id].copy()
        count = 0
        
        for session_id in session_ids:
            if self.revoke_session(session_id):
                count += 1
        
        logger.info(f"Revoked {count} sessions for user {user_id}")
        return count
    
    def refresh_session(self, session_id: str, refresh_token: str) -> Optional[Session]:
        """
        Refresh a session using refresh token.
        
        Args:
            session_id: Session ID
            refresh_token: Refresh token
            
        Returns:
            Updated session with new token, or None if invalid
        """
        session = self.sessions.get(session_id)
        
        if not session or session.refresh_token != refresh_token:
            logger.warning(f"Invalid refresh token for session {session_id}")
            return None
        
        # Get user from session
        # Note: In production, you'd fetch the user from database
        # For now, we'll just refresh the session
        session.refresh(self.token_expiry_hours)
        
        logger.info(f"Refreshed session {session_id}")
        return session
    
    def cleanup_expired_sessions(self) -> int:
        """
        Remove expired sessions.
        
        Returns:
            Number of sessions cleaned up
        """
        expired_sessions = [
            session_id for session_id, session in self.sessions.items()
            if not session.is_valid()
        ]
        
        for session_id in expired_sessions:
            session = self.sessions[session_id]
            
            # Remove from user sessions
            if session.user_id in self.user_sessions:
                self.user_sessions[session.user_id] = [
                    sid for sid in self.user_sessions[session.user_id]
                    if sid != session_id
                ]
            
            # Remove session
            del self.sessions[session_id]
        
        if expired_sessions:
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
        
        return len(expired_sessions)
    
    def get_user_sessions(self, user_id: str) -> list[Session]:
        """
        Get all active sessions for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of active sessions
        """
        if user_id not in self.user_sessions:
            return []
        
        sessions = []
        for session_id in self.user_sessions[user_id]:
            session = self.get_session(session_id)
            if session:
                sessions.append(session)
        
        return sessions


# Global session manager instance
session_manager = SessionManager()

