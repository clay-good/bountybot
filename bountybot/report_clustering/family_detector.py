"""
Vulnerability family detection.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict, Counter

from .models import VulnerabilityFamily, TrendAnalysis

logger = logging.getLogger(__name__)


class VulnerabilityFamilyDetector:
    """
    Detects and tracks vulnerability families.
    
    Features:
    - Family identification
    - Trend analysis
    - Pattern extraction
    - Evolution tracking
    
    Example:
        >>> detector = VulnerabilityFamilyDetector()
        >>> families = detector.detect_families(reports)
        >>> print(f"Found {len(families)} vulnerability families")
    """
    
    def __init__(self):
        """Initialize family detector."""
        self.families: Dict[str, VulnerabilityFamily] = {}
        logger.info("VulnerabilityFamilyDetector initialized")
    
    def detect_families(
        self,
        reports: List[Any],
        min_family_size: int = 3
    ) -> List[VulnerabilityFamily]:
        """
        Detect vulnerability families from reports.
        
        Args:
            reports: List of reports
            min_family_size: Minimum reports per family
            
        Returns:
            List of VulnerabilityFamily objects
        """
        # Group by vulnerability type
        type_groups = defaultdict(list)
        for report in reports:
            vuln_type = getattr(report, 'vulnerability_type', 'unknown')
            type_groups[vuln_type].append(report)
        
        families = []
        
        for vuln_type, group_reports in type_groups.items():
            if len(group_reports) < min_family_size:
                continue
            
            family = self._create_family(vuln_type, group_reports)
            families.append(family)
            self.families[family.family_id] = family
        
        return families
    
    def _create_family(
        self,
        vuln_type: str,
        reports: List[Any]
    ) -> VulnerabilityFamily:
        """Create vulnerability family from reports."""
        # Extract components
        components = list(set(
            getattr(r, 'affected_component', 'unknown')
            for r in reports
            if hasattr(r, 'affected_component')
        ))
        
        # Severity distribution
        sev_dist = Counter(
            str(getattr(r, 'severity', 'medium'))
            for r in reports
        )
        
        # Date range
        dates = [
            getattr(r, 'submitted_at', datetime.utcnow())
            for r in reports
        ]
        first_seen = min(dates) if dates else datetime.utcnow()
        last_seen = max(dates) if dates else datetime.utcnow()
        
        # Determine trend
        trend = self._calculate_trend(reports)
        
        # Report IDs
        report_ids = [self._get_report_id(r) for r in reports]
        
        family_id = f"family-{vuln_type.lower().replace(' ', '_')}"
        
        return VulnerabilityFamily(
            family_id=family_id,
            name=f"{vuln_type} Family",
            description=f"Family of {len(reports)} {vuln_type} vulnerabilities",
            vulnerability_types=[vuln_type],
            common_patterns=[],
            attack_vectors=[],
            affected_components=components,
            report_ids=report_ids,
            severity_distribution=dict(sev_dist),
            first_seen=first_seen,
            last_seen=last_seen,
            trend=trend
        )
    
    def analyze_trend(
        self,
        family_id: str,
        time_period_days: int = 90
    ) -> Optional[TrendAnalysis]:
        """Analyze trend for a vulnerability family."""
        if family_id not in self.families:
            return None
        
        family = self.families[family_id]
        
        # Calculate metrics
        report_count = family.get_report_count()
        days_active = (family.last_seen - family.first_seen).days + 1
        velocity = report_count / days_active if days_active > 0 else 0.0
        
        # Simple growth rate calculation
        growth_rate = 0.0  # Placeholder
        
        # Forecast
        forecast = int(velocity * 30)  # Next 30 days
        
        return TrendAnalysis(
            family_id=family_id,
            time_period_days=time_period_days,
            report_count=report_count,
            growth_rate=growth_rate,
            velocity=velocity,
            acceleration=0.0,
            trend_direction=family.trend,
            forecast_next_30_days=forecast,
            confidence=0.7
        )
    
    def _calculate_trend(self, reports: List[Any]) -> str:
        """Calculate trend direction."""
        if len(reports) < 2:
            return "stable"
        
        # Sort by date
        dated_reports = [
            (getattr(r, 'submitted_at', datetime.utcnow()), r)
            for r in reports
        ]
        dated_reports.sort(key=lambda x: x[0])
        
        # Split into halves
        mid = len(dated_reports) // 2
        first_half = dated_reports[:mid]
        second_half = dated_reports[mid:]
        
        # Compare counts
        if len(second_half) > len(first_half) * 1.2:
            return "increasing"
        elif len(second_half) < len(first_half) * 0.8:
            return "decreasing"
        else:
            return "stable"
    
    def _get_report_id(self, report: Any) -> str:
        """Get report ID."""
        if hasattr(report, 'id'):
            return str(report.id)
        if hasattr(report, 'report_id'):
            return str(report.report_id)
        return str(hash(str(report)))

