"""
IoC (Indicator of Compromise) Manager

Manages and tracks indicators of compromise.
"""

import secrets
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path
import json
import re

from .models import IoC, IoCType, ThreatSeverity


class IoC_Manager:
    """Indicator of Compromise manager."""
    
    # Regex patterns for IoC extraction
    IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    DOMAIN_PATTERN = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.IGNORECASE)
    MD5_PATTERN = re.compile(r'\b[a-f0-9]{32}\b', re.IGNORECASE)
    SHA1_PATTERN = re.compile(r'\b[a-f0-9]{40}\b', re.IGNORECASE)
    SHA256_PATTERN = re.compile(r'\b[a-f0-9]{64}\b', re.IGNORECASE)
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    
    def __init__(self, storage_dir: str = "./ioc_data"):
        """
        Initialize IoC manager.
        
        Args:
            storage_dir: Directory for IoC storage
        """
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.iocs: Dict[str, IoC] = {}
        
        # Load IoCs
        self._load_iocs()
    
    def add_ioc(self, ioc: IoC) -> bool:
        """
        Add an IoC.
        
        Args:
            ioc: IoC object
            
        Returns:
            True if added successfully
        """
        self.iocs[ioc.ioc_id] = ioc
        self._save_ioc(ioc)
        return True
    
    def extract_iocs_from_text(self, text: str) -> Dict[IoCType, List[str]]:
        """
        Extract IoCs from text.
        
        Args:
            text: Text to extract IoCs from
            
        Returns:
            Dictionary mapping IoC types to lists of values
        """
        iocs = {
            IoCType.IP_ADDRESS: list(set(self.IP_PATTERN.findall(text))),
            IoCType.DOMAIN: list(set(self.DOMAIN_PATTERN.findall(text))),
            IoCType.EMAIL: list(set(self.EMAIL_PATTERN.findall(text))),
            IoCType.FILE_HASH: []
        }
        
        # Extract hashes
        md5_hashes = self.MD5_PATTERN.findall(text)
        sha1_hashes = self.SHA1_PATTERN.findall(text)
        sha256_hashes = self.SHA256_PATTERN.findall(text)
        
        iocs[IoCType.FILE_HASH] = list(set(md5_hashes + sha1_hashes + sha256_hashes))
        
        return iocs
    
    def check_ioc(self, value: str, ioc_type: IoCType) -> Optional[IoC]:
        """
        Check if a value is a known IoC.
        
        Args:
            value: Value to check
            ioc_type: Type of IoC
            
        Returns:
            IoC object if found, None otherwise
        """
        for ioc in self.iocs.values():
            if ioc.ioc_type == ioc_type and ioc.value == value:
                # Check if expired
                if ioc.expiration and ioc.expiration < datetime.utcnow():
                    continue
                return ioc
        
        return None
    
    def get_reputation(self, value: str, ioc_type: IoCType) -> Dict[str, Any]:
        """
        Get reputation score for a value.
        
        Args:
            value: Value to check
            ioc_type: Type of IoC
            
        Returns:
            Reputation information
        """
        ioc = self.check_ioc(value, ioc_type)
        
        if not ioc:
            return {
                'known_ioc': False,
                'reputation_score': 0.0,
                'severity': None,
                'confidence': 0.0
            }
        
        return {
            'known_ioc': True,
            'reputation_score': ioc.reputation_score,
            'severity': ioc.severity.value,
            'confidence': ioc.confidence,
            'threat_actor': ioc.threat_actor,
            'campaign': ioc.campaign,
            'malware_family': ioc.malware_family,
            'first_seen': ioc.first_seen.isoformat() if ioc.first_seen else None,
            'last_seen': ioc.last_seen.isoformat() if ioc.last_seen else None,
            'sources': ioc.sources,
            'tags': ioc.tags
        }
    
    def search_iocs(
        self,
        ioc_type: Optional[IoCType] = None,
        severity: Optional[ThreatSeverity] = None,
        threat_actor: Optional[str] = None,
        campaign: Optional[str] = None,
        min_confidence: float = 0.0
    ) -> List[IoC]:
        """
        Search IoCs with filters.
        
        Args:
            ioc_type: Filter by IoC type
            severity: Filter by severity
            threat_actor: Filter by threat actor
            campaign: Filter by campaign
            min_confidence: Minimum confidence score
            
        Returns:
            List of matching IoCs
        """
        results = []
        
        for ioc in self.iocs.values():
            # Check expiration
            if ioc.expiration and ioc.expiration < datetime.utcnow():
                continue
            
            # Apply filters
            if ioc_type and ioc.ioc_type != ioc_type:
                continue
            
            if severity and ioc.severity != severity:
                continue
            
            if threat_actor and ioc.threat_actor != threat_actor:
                continue
            
            if campaign and ioc.campaign != campaign:
                continue
            
            if ioc.confidence < min_confidence:
                continue
            
            results.append(ioc)
        
        return results
    
    def get_ioc_stats(self) -> Dict[str, Any]:
        """
        Get IoC statistics.
        
        Returns:
            IoC statistics
        """
        total_iocs = len(self.iocs)
        
        # Count by type
        by_type = {}
        for ioc in self.iocs.values():
            ioc_type = ioc.ioc_type.value
            by_type[ioc_type] = by_type.get(ioc_type, 0) + 1
        
        # Count by severity
        by_severity = {}
        for ioc in self.iocs.values():
            severity = ioc.severity.value
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        # Count expired
        expired = len([
            ioc for ioc in self.iocs.values()
            if ioc.expiration and ioc.expiration < datetime.utcnow()
        ])
        
        return {
            'total_iocs': total_iocs,
            'active_iocs': total_iocs - expired,
            'expired_iocs': expired,
            'by_type': by_type,
            'by_severity': by_severity
        }
    
    def cleanup_expired(self) -> int:
        """
        Remove expired IoCs.
        
        Returns:
            Number of IoCs removed
        """
        now = datetime.utcnow()
        expired_ids = [
            ioc_id for ioc_id, ioc in self.iocs.items()
            if ioc.expiration and ioc.expiration < now
        ]
        
        for ioc_id in expired_ids:
            del self.iocs[ioc_id]
            
            # Remove file
            ioc_file = self.storage_dir / f"{ioc_id}.json"
            if ioc_file.exists():
                ioc_file.unlink()
        
        return len(expired_ids)
    
    def _load_iocs(self):
        """Load IoCs from disk."""
        for ioc_file in self.storage_dir.glob("*.json"):
            try:
                with open(ioc_file, 'r') as f:
                    data = json.load(f)
                    
                # Convert datetime strings
                if data.get('first_seen'):
                    data['first_seen'] = datetime.fromisoformat(data['first_seen'])
                if data.get('last_seen'):
                    data['last_seen'] = datetime.fromisoformat(data['last_seen'])
                if data.get('expiration'):
                    data['expiration'] = datetime.fromisoformat(data['expiration'])
                
                # Convert enums
                data['ioc_type'] = IoCType(data['ioc_type'])
                data['severity'] = ThreatSeverity(data['severity'])
                
                ioc = IoC(**data)
                self.iocs[ioc.ioc_id] = ioc
            except Exception:
                pass  # Ignore invalid files
    
    def _save_ioc(self, ioc: IoC):
        """Save IoC to disk."""
        ioc_file = self.storage_dir / f"{ioc.ioc_id}.json"
        
        data = {
            'ioc_id': ioc.ioc_id,
            'ioc_type': ioc.ioc_type.value,
            'value': ioc.value,
            'description': ioc.description,
            'severity': ioc.severity.value,
            'confidence': ioc.confidence,
            'threat_actor': ioc.threat_actor,
            'campaign': ioc.campaign,
            'malware_family': ioc.malware_family,
            'reputation_score': ioc.reputation_score,
            'first_seen': ioc.first_seen.isoformat() if ioc.first_seen else None,
            'last_seen': ioc.last_seen.isoformat() if ioc.last_seen else None,
            'expiration': ioc.expiration.isoformat() if ioc.expiration else None,
            'sources': ioc.sources,
            'tags': ioc.tags
        }
        
        try:
            with open(ioc_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass  # Ignore save errors

