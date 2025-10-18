"""
Consent Management Module

Manages user consent for data processing (GDPR compliance).
"""

import logging
import secrets
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from .models import ConsentRecord

logger = logging.getLogger(__name__)


class ConsentManager:
    """Manages user consent records."""
    
    def __init__(self):
        """Initialize consent manager."""
        self.consents: Dict[str, ConsentRecord] = {}
    
    def record_consent(
        self,
        user_id: str,
        purpose: str,
        consent_given: bool,
        consent_text: str,
        org_id: Optional[str] = None,
        expiry_days: Optional[int] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ConsentRecord:
        """
        Record user consent.
        
        Args:
            user_id: User identifier
            purpose: Purpose of data processing
            consent_given: Whether consent was given
            consent_text: Text of consent agreement
            org_id: Organization identifier
            expiry_days: Days until consent expires
            ip_address: IP address of user
            user_agent: User agent string
            metadata: Additional metadata
            
        Returns:
            Consent record
        """
        consent_id = f"consent_{secrets.token_hex(8)}"
        
        consent = ConsentRecord(
            consent_id=consent_id,
            user_id=user_id,
            org_id=org_id,
            purpose=purpose,
            consent_given=consent_given,
            consent_text=consent_text,
            consent_date=datetime.utcnow() if consent_given else None,
            expiry_date=datetime.utcnow() + timedelta(days=expiry_days) if expiry_days else None,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata or {}
        )
        
        self.consents[consent_id] = consent
        
        logger.info(f"Recorded consent for user {user_id}, purpose: {purpose}, given: {consent_given}")
        
        return consent
    
    def withdraw_consent(
        self,
        user_id: str,
        purpose: str
    ) -> List[ConsentRecord]:
        """
        Withdraw user consent for a purpose.
        
        Args:
            user_id: User identifier
            purpose: Purpose to withdraw consent for
            
        Returns:
            List of withdrawn consent records
        """
        withdrawn = []
        
        for consent in self.consents.values():
            if consent.user_id == user_id and consent.purpose == purpose:
                if consent.consent_given and not consent.withdrawn_date:
                    consent.withdrawn_date = datetime.utcnow()
                    consent.consent_given = False
                    withdrawn.append(consent)
                    logger.info(f"Withdrew consent {consent.consent_id} for user {user_id}")
        
        return withdrawn
    
    def check_consent(
        self,
        user_id: str,
        purpose: str,
        org_id: Optional[str] = None
    ) -> bool:
        """
        Check if user has valid consent for purpose.
        
        Args:
            user_id: User identifier
            purpose: Purpose to check
            org_id: Organization identifier
            
        Returns:
            True if valid consent exists
        """
        for consent in self.consents.values():
            if consent.user_id == user_id and consent.purpose == purpose:
                # Check org match if specified
                if org_id and consent.org_id != org_id:
                    continue
                
                # Check if consent is valid
                if consent.is_valid():
                    return True
        
        return False
    
    def get_user_consents(
        self,
        user_id: str,
        org_id: Optional[str] = None,
        include_withdrawn: bool = False
    ) -> List[ConsentRecord]:
        """
        Get all consents for a user.
        
        Args:
            user_id: User identifier
            org_id: Organization identifier
            include_withdrawn: Include withdrawn consents
            
        Returns:
            List of consent records
        """
        consents = []
        
        for consent in self.consents.values():
            if consent.user_id != user_id:
                continue
            
            if org_id and consent.org_id != org_id:
                continue
            
            if not include_withdrawn and consent.withdrawn_date:
                continue
            
            consents.append(consent)
        
        return consents
    
    def get_consent_by_id(self, consent_id: str) -> Optional[ConsentRecord]:
        """Get consent record by ID."""
        return self.consents.get(consent_id)
    
    def update_consent(
        self,
        consent_id: str,
        consent_given: Optional[bool] = None,
        expiry_date: Optional[datetime] = None
    ) -> Optional[ConsentRecord]:
        """
        Update consent record.
        
        Args:
            consent_id: Consent identifier
            consent_given: New consent status
            expiry_date: New expiry date
            
        Returns:
            Updated consent record or None
        """
        consent = self.consents.get(consent_id)
        
        if not consent:
            return None
        
        if consent_given is not None:
            consent.consent_given = consent_given
            if consent_given:
                consent.consent_date = datetime.utcnow()
                consent.withdrawn_date = None
            else:
                consent.withdrawn_date = datetime.utcnow()
        
        if expiry_date is not None:
            consent.expiry_date = expiry_date
        
        logger.info(f"Updated consent {consent_id}")
        
        return consent
    
    def get_expired_consents(self) -> List[ConsentRecord]:
        """
        Get all expired consents.
        
        Returns:
            List of expired consent records
        """
        expired = []
        now = datetime.utcnow()
        
        for consent in self.consents.values():
            if consent.expiry_date and now > consent.expiry_date:
                if consent.consent_given and not consent.withdrawn_date:
                    expired.append(consent)
        
        return expired
    
    def get_consent_report(
        self,
        org_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate consent report.
        
        Args:
            org_id: Organization identifier
            
        Returns:
            Report dictionary
        """
        consents = list(self.consents.values())
        
        if org_id:
            consents = [c for c in consents if c.org_id == org_id]
        
        total_consents = len(consents)
        active_consents = sum(1 for c in consents if c.is_valid())
        withdrawn_consents = sum(1 for c in consents if c.withdrawn_date)
        expired_consents = sum(
            1 for c in consents
            if c.expiry_date and datetime.utcnow() > c.expiry_date
        )
        
        # Group by purpose
        by_purpose = {}
        for consent in consents:
            purpose = consent.purpose
            if purpose not in by_purpose:
                by_purpose[purpose] = {
                    'total': 0,
                    'active': 0,
                    'withdrawn': 0
                }
            
            by_purpose[purpose]['total'] += 1
            if consent.is_valid():
                by_purpose[purpose]['active'] += 1
            if consent.withdrawn_date:
                by_purpose[purpose]['withdrawn'] += 1
        
        return {
            'total_consents': total_consents,
            'active_consents': active_consents,
            'withdrawn_consents': withdrawn_consents,
            'expired_consents': expired_consents,
            'by_purpose': by_purpose,
            'consent_rate': (active_consents / total_consents * 100) if total_consents > 0 else 0
        }
    
    def export_user_consents(
        self,
        user_id: str,
        org_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Export all consent data for a user (GDPR data portability).
        
        Args:
            user_id: User identifier
            org_id: Organization identifier
            
        Returns:
            User consent data
        """
        consents = self.get_user_consents(user_id, org_id, include_withdrawn=True)
        
        return {
            'user_id': user_id,
            'org_id': org_id,
            'export_date': datetime.utcnow().isoformat(),
            'total_consents': len(consents),
            'consents': [
                {
                    'consent_id': c.consent_id,
                    'purpose': c.purpose,
                    'consent_given': c.consent_given,
                    'consent_text': c.consent_text,
                    'consent_date': c.consent_date.isoformat() if c.consent_date else None,
                    'expiry_date': c.expiry_date.isoformat() if c.expiry_date else None,
                    'withdrawn_date': c.withdrawn_date.isoformat() if c.withdrawn_date else None,
                    'is_valid': c.is_valid()
                }
                for c in consents
            ]
        }
    
    def delete_user_consents(
        self,
        user_id: str,
        org_id: Optional[str] = None
    ) -> int:
        """
        Delete all consent records for a user (GDPR right to erasure).
        
        Args:
            user_id: User identifier
            org_id: Organization identifier
            
        Returns:
            Number of consents deleted
        """
        to_delete = []
        
        for consent_id, consent in self.consents.items():
            if consent.user_id == user_id:
                if org_id is None or consent.org_id == org_id:
                    to_delete.append(consent_id)
        
        for consent_id in to_delete:
            del self.consents[consent_id]
        
        logger.info(f"Deleted {len(to_delete)} consent records for user {user_id}")
        
        return len(to_delete)

