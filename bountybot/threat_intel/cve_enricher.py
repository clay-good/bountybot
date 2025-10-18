"""
CVE/NVD Enrichment Engine

Provides automatic CVE lookup, enrichment, and validation against NVD database.
"""

import re
import secrets
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path
import json

from .models import CVEData


class CVEEnricher:
    """CVE/NVD enrichment engine."""
    
    # CVE ID pattern: CVE-YYYY-NNNNN
    CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
    
    def __init__(self, cache_dir: str = "./cve_cache", api_key: Optional[str] = None):
        """
        Initialize CVE enricher.
        
        Args:
            cache_dir: Directory for caching CVE data
            api_key: Optional NVD API key for higher rate limits
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.api_key = api_key
        self.cache: Dict[str, CVEData] = {}
        
        # Load cache
        self._load_cache()
    
    def extract_cve_ids(self, text: str) -> List[str]:
        """
        Extract CVE IDs from text.
        
        Args:
            text: Text to search for CVE IDs
            
        Returns:
            List of CVE IDs found
        """
        matches = self.CVE_PATTERN.findall(text)
        return [cve.upper() for cve in matches]
    
    def enrich_cve(self, cve_id: str, force_refresh: bool = False) -> Optional[CVEData]:
        """
        Enrich CVE with data from NVD.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)
            force_refresh: Force refresh from NVD even if cached
            
        Returns:
            CVEData object or None if not found
        """
        cve_id = cve_id.upper()
        
        # Check cache
        if not force_refresh and cve_id in self.cache:
            return self.cache[cve_id]
        
        # Fetch from NVD (simulated for demo)
        cve_data = self._fetch_from_nvd(cve_id)
        
        if cve_data:
            # Cache the result
            self.cache[cve_id] = cve_data
            self._save_to_cache(cve_id, cve_data)
        
        return cve_data
    
    def enrich_text(self, text: str) -> Dict[str, CVEData]:
        """
        Extract and enrich all CVEs found in text.
        
        Args:
            text: Text to search and enrich
            
        Returns:
            Dictionary mapping CVE IDs to CVEData
        """
        cve_ids = self.extract_cve_ids(text)
        enriched = {}
        
        for cve_id in cve_ids:
            cve_data = self.enrich_cve(cve_id)
            if cve_data:
                enriched[cve_id] = cve_data
        
        return enriched
    
    def validate_cvss_score(self, cve_id: str, reported_score: float) -> Dict[str, Any]:
        """
        Validate reported CVSS score against NVD data.
        
        Args:
            cve_id: CVE identifier
            reported_score: CVSS score reported in submission
            
        Returns:
            Validation result with match status and official score
        """
        cve_data = self.enrich_cve(cve_id)
        
        if not cve_data:
            return {
                'valid': False,
                'reason': 'CVE not found in NVD',
                'official_score': None
            }
        
        official_score = cve_data.cvss_v3_score or cve_data.cvss_v2_score
        
        if not official_score:
            return {
                'valid': False,
                'reason': 'No CVSS score available in NVD',
                'official_score': None
            }
        
        # Allow 0.5 point tolerance
        score_diff = abs(reported_score - official_score)
        
        return {
            'valid': score_diff <= 0.5,
            'reported_score': reported_score,
            'official_score': official_score,
            'difference': score_diff,
            'reason': 'Score matches' if score_diff <= 0.5 else f'Score differs by {score_diff:.1f} points'
        }
    
    def get_patch_info(self, cve_id: str) -> Dict[str, Any]:
        """
        Get patch availability information for CVE.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            Patch information including availability and URLs
        """
        cve_data = self.enrich_cve(cve_id)
        
        if not cve_data:
            return {
                'patch_available': False,
                'patch_urls': [],
                'reason': 'CVE not found'
            }
        
        return {
            'patch_available': cve_data.patch_available,
            'patch_urls': cve_data.patch_urls,
            'last_modified': cve_data.last_modified_date.isoformat()
        }
    
    def get_affected_products(self, cve_id: str) -> List[str]:
        """
        Get list of affected products for CVE.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            List of affected product names
        """
        cve_data = self.enrich_cve(cve_id)
        return cve_data.affected_products if cve_data else []
    
    def _fetch_from_nvd(self, cve_id: str) -> Optional[CVEData]:
        """
        Fetch CVE data from NVD API.
        
        In production, this would make actual API calls to NVD.
        For demo purposes, we simulate with sample data.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            CVEData object or None
        """
        # Simulated NVD data for demo
        # In production, use: https://services.nvd.nist.gov/rest/json/cves/2.0
        
        # Sample data for Log4Shell
        if cve_id == "CVE-2021-44228":
            return CVEData(
                cve_id=cve_id,
                description="Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                published_date=datetime(2021, 12, 10),
                last_modified_date=datetime(2023, 11, 7),
                cvss_v3_score=10.0,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cvss_v2_score=9.3,
                cvss_v2_vector="AV:N/AC:M/Au:N/C:C/I:C/A:C",
                cwe_ids=["CWE-502", "CWE-400", "CWE-20"],
                affected_products=[
                    "Apache Log4j 2.0-beta9 to 2.15.0",
                    "Apache Log4j 2.0-beta9 to 2.12.1",
                    "Apache Log4j 2.0-beta9 to 2.3.0"
                ],
                references=[
                    "https://logging.apache.org/log4j/2.x/security.html",
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                ],
                patch_available=True,
                patch_urls=[
                    "https://logging.apache.org/log4j/2.x/download.html"
                ],
                source="NVD"
            )
        
        # Sample data for Heartbleed
        elif cve_id == "CVE-2014-0160":
            return CVEData(
                cve_id=cve_id,
                description="The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory.",
                published_date=datetime(2014, 4, 7),
                last_modified_date=datetime(2020, 10, 20),
                cvss_v3_score=7.5,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cvss_v2_score=5.0,
                cvss_v2_vector="AV:N/AC:L/Au:N/C:P/I:N/A:N",
                cwe_ids=["CWE-125", "CWE-200"],
                affected_products=[
                    "OpenSSL 1.0.1 through 1.0.1f",
                    "OpenSSL 1.0.2-beta through 1.0.2-beta1"
                ],
                references=[
                    "https://www.openssl.org/news/secadv/20140407.txt",
                    "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
                ],
                patch_available=True,
                patch_urls=[
                    "https://www.openssl.org/source/"
                ],
                source="NVD"
            )
        
        # Generic CVE data for demo
        else:
            return CVEData(
                cve_id=cve_id,
                description=f"Vulnerability {cve_id} - detailed description would be fetched from NVD",
                published_date=datetime.utcnow(),
                last_modified_date=datetime.utcnow(),
                cvss_v3_score=7.5,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cwe_ids=["CWE-79"],
                affected_products=["Various products"],
                references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                patch_available=False,
                source="NVD"
            )
    
    def _load_cache(self):
        """Load CVE cache from disk."""
        cache_file = self.cache_dir / "cve_cache.json"
        
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                    
                for cve_id, cve_dict in data.items():
                    # Convert datetime strings back to datetime objects
                    cve_dict['published_date'] = datetime.fromisoformat(cve_dict['published_date'])
                    cve_dict['last_modified_date'] = datetime.fromisoformat(cve_dict['last_modified_date'])
                    
                    self.cache[cve_id] = CVEData(**cve_dict)
            except Exception:
                pass  # Ignore cache errors
    
    def _save_to_cache(self, cve_id: str, cve_data: CVEData):
        """Save CVE data to cache."""
        cache_file = self.cache_dir / "cve_cache.json"
        
        # Load existing cache
        cache_dict = {}
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    cache_dict = json.load(f)
            except Exception:
                pass
        
        # Add new entry
        cve_dict = {
            'cve_id': cve_data.cve_id,
            'description': cve_data.description,
            'published_date': cve_data.published_date.isoformat(),
            'last_modified_date': cve_data.last_modified_date.isoformat(),
            'cvss_v3_score': cve_data.cvss_v3_score,
            'cvss_v3_vector': cve_data.cvss_v3_vector,
            'cvss_v2_score': cve_data.cvss_v2_score,
            'cvss_v2_vector': cve_data.cvss_v2_vector,
            'cwe_ids': cve_data.cwe_ids,
            'affected_products': cve_data.affected_products,
            'references': cve_data.references,
            'patch_available': cve_data.patch_available,
            'patch_urls': cve_data.patch_urls,
            'source': cve_data.source
        }
        
        cache_dict[cve_id] = cve_dict
        
        # Save to disk
        try:
            with open(cache_file, 'w') as f:
                json.dump(cache_dict, f, indent=2)
        except Exception:
            pass  # Ignore save errors

