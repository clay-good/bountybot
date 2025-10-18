"""
Risk Contextualizer

Provides threat-informed risk scoring and contextualization.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime

from .cve_enricher import CVEEnricher
from .exploit_correlator import ExploitCorrelator
from .vulnerability_intelligence import VulnerabilityIntelligenceEngine
from .mitre_mapper import MitreMapper
from .threat_actor_profiler import ThreatActorProfiler


class RiskContextualizer:
    """Threat-informed risk contextualization engine."""
    
    def __init__(
        self,
        cve_enricher: Optional[CVEEnricher] = None,
        exploit_correlator: Optional[ExploitCorrelator] = None,
        vuln_intel: Optional[VulnerabilityIntelligenceEngine] = None,
        mitre_mapper: Optional[MitreMapper] = None,
        threat_profiler: Optional[ThreatActorProfiler] = None
    ):
        """
        Initialize risk contextualizer.
        
        Args:
            cve_enricher: CVE enrichment engine
            exploit_correlator: Exploit correlation engine
            vuln_intel: Vulnerability intelligence engine
            mitre_mapper: MITRE ATT&CK mapper
            threat_profiler: Threat actor profiler
        """
        self.cve_enricher = cve_enricher or CVEEnricher()
        self.exploit_correlator = exploit_correlator or ExploitCorrelator()
        self.vuln_intel = vuln_intel or VulnerabilityIntelligenceEngine()
        self.mitre_mapper = mitre_mapper or MitreMapper()
        self.threat_profiler = threat_profiler or ThreatActorProfiler()
    
    def contextualize_vulnerability(
        self,
        cve_id: str,
        base_cvss_score: float,
        description: str = "",
        affected_systems: int = 0
    ) -> Dict[str, Any]:
        """
        Provide comprehensive risk context for vulnerability.
        
        Args:
            cve_id: CVE identifier
            base_cvss_score: Base CVSS score
            description: Vulnerability description
            affected_systems: Number of affected systems
            
        Returns:
            Comprehensive risk context
        """
        context = {
            'cve_id': cve_id,
            'base_cvss_score': base_cvss_score,
            'contextualized_score': base_cvss_score,
            'risk_multiplier': 1.0,
            'risk_factors': []
        }
        
        # 1. CVE Enrichment
        cve_data = self.cve_enricher.enrich_cve(cve_id)
        if cve_data:
            context['cve_data'] = {
                'description': cve_data.description,
                'published_date': cve_data.published_date.isoformat(),
                'cvss_v3_score': cve_data.cvss_v3_score,
                'cwe_ids': cve_data.cwe_ids,
                'patch_available': cve_data.patch_available
            }
            
            if not cve_data.patch_available:
                context['risk_multiplier'] *= 1.3
                context['risk_factors'].append("No patch available (+30%)")
        
        # 2. Exploit Correlation
        exploit_summary = self.exploit_correlator.get_exploit_summary(cve_id)
        context['exploit_data'] = exploit_summary
        
        if exploit_summary['exploit_available']:
            context['risk_multiplier'] *= 1.5
            context['risk_factors'].append(f"Public exploits available (+50%)")
            
            if exploit_summary['metasploit_modules'] > 0:
                context['risk_multiplier'] *= 1.2
                context['risk_factors'].append("Metasploit module exists (+20%)")
        
        # 3. Vulnerability Intelligence
        vuln_intel_data = self.vuln_intel.track_vulnerability(
            cve_id,
            risk_score=base_cvss_score,
            affected_systems=affected_systems
        )
        
        # Check if actively exploited
        if vuln_intel_data.actively_exploited:
            context['risk_multiplier'] *= 2.0
            context['risk_factors'].append("Actively exploited in wild (+100%)")
        
        # Check trending
        trending_score = self.vuln_intel.calculate_trending_score(cve_id)
        if trending_score > 0.7:
            context['risk_multiplier'] *= 1.4
            context['risk_factors'].append(f"Highly trending (score: {trending_score:.2f}) (+40%)")
        elif trending_score > 0.5:
            context['risk_multiplier'] *= 1.2
            context['risk_factors'].append(f"Trending (score: {trending_score:.2f}) (+20%)")
        
        context['trending_score'] = trending_score
        
        # Check zero-day
        zero_day_result = self.vuln_intel.detect_zero_day(cve_id)
        if zero_day_result['is_zero_day']:
            context['risk_multiplier'] *= 1.8
            context['risk_factors'].append("Potential zero-day (+80%)")
        
        context['zero_day'] = zero_day_result
        
        # 4. MITRE ATT&CK Mapping
        techniques = self.mitre_mapper.map_vulnerability_to_techniques(cve_id, description)
        context['mitre_techniques'] = [
            {
                'technique_id': t.technique_id,
                'name': t.name,
                'tactic': t.tactic
            }
            for t in techniques
        ]
        
        # 5. Exploit Likelihood
        exploit_likelihood = self.vuln_intel.predict_exploit_likelihood(cve_id)
        context['exploit_likelihood'] = exploit_likelihood
        
        if exploit_likelihood['likelihood'] > 0.7:
            context['risk_multiplier'] *= 1.3
            context['risk_factors'].append(f"High exploit likelihood ({exploit_likelihood['likelihood']:.0%}) (+30%)")
        
        # 6. Calculate final contextualized score
        context['contextualized_score'] = min(base_cvss_score * context['risk_multiplier'], 10.0)
        
        # 7. Risk level
        if context['contextualized_score'] >= 9.0:
            context['risk_level'] = "CRITICAL"
        elif context['contextualized_score'] >= 7.0:
            context['risk_level'] = "HIGH"
        elif context['contextualized_score'] >= 4.0:
            context['risk_level'] = "MEDIUM"
        else:
            context['risk_level'] = "LOW"
        
        # 8. Recommendations
        context['recommendations'] = self._generate_recommendations(context)
        
        return context
    
    def assess_threat_landscape(
        self,
        industry: Optional[str] = None,
        country: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Assess threat landscape for organization.
        
        Args:
            industry: Target industry
            country: Target country
            
        Returns:
            Threat landscape assessment
        """
        assessment = {
            'industry': industry,
            'country': country,
            'threat_actors': [],
            'trending_vulnerabilities': [],
            'actively_exploited': []
        }
        
        # Find relevant threat actors
        actors = self.threat_profiler.search_actors(
            target_industry=industry,
            target_country=country
        )
        
        assessment['threat_actors'] = [
            {
                'actor_id': actor.actor_id,
                'name': actor.name,
                'sophistication': actor.sophistication,
                'motivation': actor.motivation
            }
            for actor in actors[:5]
        ]
        
        # Get trending vulnerabilities
        trending = self.vuln_intel.get_trending_vulnerabilities(limit=10)
        assessment['trending_vulnerabilities'] = [
            {
                'vuln_id': v.vuln_id,
                'trending_score': v.trending_score,
                'risk_score': v.risk_score,
                'actively_exploited': v.actively_exploited
            }
            for v in trending
        ]
        
        # Get actively exploited
        exploited = self.vuln_intel.get_actively_exploited()
        assessment['actively_exploited'] = [
            {
                'vuln_id': v.vuln_id,
                'risk_score': v.risk_score,
                'exploit_in_wild': v.exploit_in_wild
            }
            for v in exploited[:10]
        ]
        
        # Overall risk level
        if len(exploited) > 10 or len(actors) > 3:
            assessment['overall_risk'] = "HIGH"
        elif len(exploited) > 5 or len(actors) > 1:
            assessment['overall_risk'] = "MEDIUM"
        else:
            assessment['overall_risk'] = "LOW"
        
        return assessment
    
    def prioritize_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Prioritize vulnerabilities based on threat context.
        
        Args:
            vulnerabilities: List of vulnerabilities with CVE IDs and scores
            
        Returns:
            Prioritized list with context
        """
        prioritized = []
        
        for vuln in vulnerabilities:
            cve_id = vuln.get('cve_id', '')
            base_score = vuln.get('cvss_score', 0.0)
            description = vuln.get('description', '')
            
            if cve_id:
                context = self.contextualize_vulnerability(
                    cve_id,
                    base_score,
                    description
                )
                
                prioritized.append({
                    **vuln,
                    'contextualized_score': context['contextualized_score'],
                    'risk_multiplier': context['risk_multiplier'],
                    'risk_level': context['risk_level'],
                    'risk_factors': context['risk_factors'],
                    'exploit_available': context['exploit_data']['exploit_available'],
                    'trending_score': context['trending_score']
                })
            else:
                prioritized.append({
                    **vuln,
                    'contextualized_score': base_score,
                    'risk_multiplier': 1.0,
                    'risk_level': 'UNKNOWN'
                })
        
        # Sort by contextualized score
        prioritized.sort(key=lambda v: v['contextualized_score'], reverse=True)
        
        return prioritized
    
    def _generate_recommendations(self, context: Dict[str, Any]) -> List[str]:
        """Generate remediation recommendations."""
        recommendations = []
        
        if context['risk_level'] == "CRITICAL":
            recommendations.append("URGENT: Immediate patching required")
        
        if context.get('exploit_data', {}).get('exploit_available'):
            recommendations.append("Public exploits available - prioritize patching")
        
        if context.get('zero_day', {}).get('is_zero_day'):
            recommendations.append("Potential zero-day - implement compensating controls")
        
        if context.get('cve_data', {}).get('patch_available'):
            recommendations.append("Patch available - deploy immediately")
        else:
            recommendations.append("No patch available - implement workarounds and monitoring")
        
        if context.get('trending_score', 0) > 0.7:
            recommendations.append("Highly trending vulnerability - expect increased attack attempts")
        
        if not recommendations:
            recommendations.append("Monitor for exploit development and patch when available")
        
        return recommendations

