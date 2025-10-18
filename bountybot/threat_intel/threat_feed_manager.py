"""
Threat Intelligence Feed Manager

Manages multiple threat intelligence feeds with STIX/TAXII support.
"""

import secrets
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path
import json

from .models import ThreatFeed, ThreatIndicator, IoCType, ThreatSeverity


class ThreatFeedManager:
    """Threat intelligence feed manager."""
    
    def __init__(self, config_dir: str = "./threat_feeds"):
        """
        Initialize threat feed manager.
        
        Args:
            config_dir: Directory for feed configurations
        """
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.feeds: Dict[str, ThreatFeed] = {}
        self.indicators: Dict[str, ThreatIndicator] = {}
        
        # Load feeds
        self._load_feeds()
    
    def add_feed(self, feed: ThreatFeed) -> bool:
        """
        Add a threat intelligence feed.
        
        Args:
            feed: Threat feed configuration
            
        Returns:
            True if added successfully
        """
        self.feeds[feed.feed_id] = feed
        self._save_feed(feed)
        return True
    
    def remove_feed(self, feed_id: str) -> bool:
        """
        Remove a threat intelligence feed.
        
        Args:
            feed_id: Feed identifier
            
        Returns:
            True if removed successfully
        """
        if feed_id in self.feeds:
            del self.feeds[feed_id]
            
            # Remove config file
            config_file = self.config_dir / f"{feed_id}.json"
            if config_file.exists():
                config_file.unlink()
            
            return True
        return False
    
    def update_feed(self, feed_id: str) -> Dict[str, Any]:
        """
        Update indicators from a feed.
        
        Args:
            feed_id: Feed identifier
            
        Returns:
            Update statistics
        """
        if feed_id not in self.feeds:
            return {'success': False, 'error': 'Feed not found'}
        
        feed = self.feeds[feed_id]
        
        if not feed.enabled:
            return {'success': False, 'error': 'Feed is disabled'}
        
        # Fetch indicators from feed
        new_indicators = self._fetch_indicators(feed)
        
        # Filter by confidence
        filtered_indicators = [
            ind for ind in new_indicators
            if ind.confidence >= feed.min_confidence
        ]
        
        # Filter by indicator type if specified
        if feed.indicator_types:
            filtered_indicators = [
                ind for ind in filtered_indicators
                if ind.indicator_type in feed.indicator_types
            ]
        
        # Add to indicator store
        added_count = 0
        updated_count = 0
        
        for indicator in filtered_indicators:
            if indicator.indicator_id in self.indicators:
                updated_count += 1
            else:
                added_count += 1
            
            self.indicators[indicator.indicator_id] = indicator
        
        # Update feed metadata
        feed.last_update = datetime.utcnow()
        feed.total_indicators = len(filtered_indicators)
        self._save_feed(feed)
        
        return {
            'success': True,
            'feed_id': feed_id,
            'added': added_count,
            'updated': updated_count,
            'total': len(filtered_indicators),
            'last_update': feed.last_update.isoformat()
        }
    
    def update_all_feeds(self) -> Dict[str, Any]:
        """
        Update all enabled feeds.
        
        Returns:
            Update statistics for all feeds
        """
        results = {}
        
        for feed_id, feed in self.feeds.items():
            if feed.enabled:
                results[feed_id] = self.update_feed(feed_id)
        
        return results
    
    def search_indicators(
        self,
        value: Optional[str] = None,
        indicator_type: Optional[IoCType] = None,
        min_confidence: float = 0.0,
        threat_actors: Optional[List[str]] = None
    ) -> List[ThreatIndicator]:
        """
        Search threat indicators.
        
        Args:
            value: Indicator value to search for
            indicator_type: Type of indicator
            min_confidence: Minimum confidence score
            threat_actors: Filter by threat actors
            
        Returns:
            List of matching indicators
        """
        results = []
        
        for indicator in self.indicators.values():
            # Filter by value
            if value and value.lower() not in indicator.value.lower():
                continue
            
            # Filter by type
            if indicator_type and indicator.indicator_type != indicator_type:
                continue
            
            # Filter by confidence
            if indicator.confidence < min_confidence:
                continue
            
            # Filter by threat actors
            if threat_actors:
                if not any(actor in indicator.threat_actors for actor in threat_actors):
                    continue
            
            results.append(indicator)
        
        return results
    
    def check_ioc(self, value: str, ioc_type: IoCType) -> Optional[ThreatIndicator]:
        """
        Check if a value is a known IoC.
        
        Args:
            value: Value to check (IP, domain, hash, etc.)
            ioc_type: Type of IoC
            
        Returns:
            ThreatIndicator if found, None otherwise
        """
        for indicator in self.indicators.values():
            if indicator.indicator_type == ioc_type and indicator.value == value:
                return indicator
        
        return None
    
    def get_feed_stats(self) -> Dict[str, Any]:
        """
        Get statistics for all feeds.
        
        Returns:
            Feed statistics
        """
        total_feeds = len(self.feeds)
        enabled_feeds = len([f for f in self.feeds.values() if f.enabled])
        total_indicators = len(self.indicators)
        
        # Count by type
        indicators_by_type = {}
        for indicator in self.indicators.values():
            ioc_type = indicator.indicator_type.value
            indicators_by_type[ioc_type] = indicators_by_type.get(ioc_type, 0) + 1
        
        # Count by severity
        indicators_by_severity = {}
        for indicator in self.indicators.values():
            severity = indicator.severity.value
            indicators_by_severity[severity] = indicators_by_severity.get(severity, 0) + 1
        
        return {
            'total_feeds': total_feeds,
            'enabled_feeds': enabled_feeds,
            'total_indicators': total_indicators,
            'indicators_by_type': indicators_by_type,
            'indicators_by_severity': indicators_by_severity,
            'feeds': [self._feed_to_dict(f) for f in self.feeds.values()]
        }
    
    def _fetch_indicators(self, feed: ThreatFeed) -> List[ThreatIndicator]:
        """
        Fetch indicators from a feed.
        
        In production, this would make actual API calls or parse feed data.
        For demo, we simulate with sample data.
        """
        # Simulated threat indicators
        indicators = []
        
        # Sample malicious IPs
        sample_ips = [
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1"
        ]
        
        for ip in sample_ips:
            indicators.append(ThreatIndicator(
                indicator_id=f"ind_{secrets.token_hex(8)}",
                indicator_type=IoCType.IP_ADDRESS,
                value=ip,
                threat_types=["c2", "malware"],
                severity=ThreatSeverity.HIGH,
                confidence=0.85,
                threat_actors=["APT28", "APT29"],
                campaigns=["Operation XYZ"],
                first_seen=datetime.utcnow() - timedelta(days=30),
                last_seen=datetime.utcnow() - timedelta(days=1),
                description=f"Known C2 server IP address",
                tags=["c2", "apt", "russia"],
                sources=[feed.name]
            ))
        
        # Sample malicious domains
        sample_domains = [
            "malicious-example.com",
            "phishing-site.net"
        ]
        
        for domain in sample_domains:
            indicators.append(ThreatIndicator(
                indicator_id=f"ind_{secrets.token_hex(8)}",
                indicator_type=IoCType.DOMAIN,
                value=domain,
                threat_types=["phishing", "malware"],
                severity=ThreatSeverity.MEDIUM,
                confidence=0.75,
                first_seen=datetime.utcnow() - timedelta(days=7),
                last_seen=datetime.utcnow(),
                description=f"Phishing domain",
                tags=["phishing", "credential-theft"],
                sources=[feed.name]
            ))
        
        return indicators
    
    def _feed_to_dict(self, feed: ThreatFeed) -> Dict[str, Any]:
        """Convert feed to dictionary."""
        return {
            'feed_id': feed.feed_id,
            'name': feed.name,
            'enabled': feed.enabled,
            'total_indicators': feed.total_indicators,
            'last_update': feed.last_update.isoformat() if feed.last_update else None,
            'priority': feed.priority
        }
    
    def _load_feeds(self):
        """Load feed configurations from disk."""
        for config_file in self.config_dir.glob("*.json"):
            try:
                with open(config_file, 'r') as f:
                    data = json.load(f)
                    
                # Convert datetime strings
                if data.get('last_update'):
                    data['last_update'] = datetime.fromisoformat(data['last_update'])
                
                # Convert indicator types
                if data.get('indicator_types'):
                    data['indicator_types'] = [IoCType(t) for t in data['indicator_types']]
                
                feed = ThreatFeed(**data)
                self.feeds[feed.feed_id] = feed
            except Exception:
                pass  # Ignore invalid configs
    
    def _save_feed(self, feed: ThreatFeed):
        """Save feed configuration to disk."""
        config_file = self.config_dir / f"{feed.feed_id}.json"
        
        data = {
            'feed_id': feed.feed_id,
            'name': feed.name,
            'feed_type': feed.feed_type,
            'url': feed.url,
            'enabled': feed.enabled,
            'update_frequency': feed.update_frequency,
            'priority': feed.priority,
            'indicator_types': [t.value for t in feed.indicator_types],
            'min_confidence': feed.min_confidence,
            'last_update': feed.last_update.isoformat() if feed.last_update else None,
            'total_indicators': feed.total_indicators,
            'description': feed.description,
            'tags': feed.tags
        }
        
        try:
            with open(config_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass  # Ignore save errors

