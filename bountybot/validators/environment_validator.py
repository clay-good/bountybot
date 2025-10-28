"""
Environment-Specific Validator - Validates vulnerabilities against deployment environment.

This module checks if reported vulnerabilities actually apply to the organization's
specific deployment environment by analyzing:
- Network topology and accessibility
- Feature flags and configuration
- Access controls and authentication requirements
- Deployment architecture (cloud, on-prem, hybrid)
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class EnvironmentType(Enum):
    """Types of deployment environments."""
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"


class AccessLevel(Enum):
    """Access levels for resources."""
    PUBLIC = "public"
    AUTHENTICATED = "authenticated"
    INTERNAL = "internal"
    ADMIN = "admin"


class ApplicabilityLevel(Enum):
    """How applicable a vulnerability is to the environment."""
    APPLICABLE = "applicable"  # Vulnerability applies to this environment
    PARTIALLY_APPLICABLE = "partially_applicable"  # Applies with conditions
    NOT_APPLICABLE = "not_applicable"  # Does not apply
    UNKNOWN = "unknown"  # Cannot determine


@dataclass
class EnvironmentConfig:
    """Configuration for a deployment environment."""
    environment_type: EnvironmentType
    network_topology: Dict[str, Any] = field(default_factory=dict)
    feature_flags: Dict[str, bool] = field(default_factory=dict)
    access_controls: Dict[str, AccessLevel] = field(default_factory=dict)
    deployed_services: List[str] = field(default_factory=list)
    cloud_provider: Optional[str] = None
    firewall_rules: List[Dict[str, Any]] = field(default_factory=list)
    authentication_required: bool = True
    public_endpoints: List[str] = field(default_factory=list)


@dataclass
class ApplicabilityCheck:
    """Result of checking if vulnerability applies to environment."""
    check_name: str
    applicable: bool
    reason: str
    confidence: float = 1.0


@dataclass
class EnvironmentValidationResult:
    """Results from environment-specific validation."""
    applicability: ApplicabilityLevel
    confidence: float
    checks_performed: List[ApplicabilityCheck]
    affected_environments: List[EnvironmentType]
    recommendations: List[str] = field(default_factory=list)
    details: str = ""


class EnvironmentValidator:
    """
    Validates if vulnerabilities apply to specific deployment environments.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize environment validator."""
        self.config = config or {}
        self.environments: Dict[str, EnvironmentConfig] = {}
    
    def add_environment(self, name: str, env_config: EnvironmentConfig):
        """Add an environment configuration."""
        self.environments[name] = env_config
        logger.info(f"Added environment: {name} ({env_config.environment_type.value})")
    
    def validate(self, vulnerability_report: Dict[str, Any],
                environment_name: Optional[str] = None) -> EnvironmentValidationResult:
        """
        Validate if vulnerability applies to environment(s).
        
        Args:
            vulnerability_report: Vulnerability report details
            environment_name: Specific environment to check (or all if None)
        
        Returns:
            EnvironmentValidationResult with applicability assessment
        """
        if environment_name:
            if environment_name not in self.environments:
                return EnvironmentValidationResult(
                    applicability=ApplicabilityLevel.UNKNOWN,
                    confidence=0.0,
                    checks_performed=[],
                    affected_environments=[],
                    details=f"Environment '{environment_name}' not found"
                )
            environments_to_check = {environment_name: self.environments[environment_name]}
        else:
            environments_to_check = self.environments
        
        all_checks = []
        affected_environments = []
        
        for env_name, env_config in environments_to_check.items():
            checks = self._check_environment(vulnerability_report, env_config)
            all_checks.extend(checks)
            
            # If any check shows it's applicable, mark environment as affected
            if any(check.applicable for check in checks):
                affected_environments.append(env_config.environment_type)
        
        # Calculate overall applicability
        applicability = self._calculate_applicability(all_checks)
        confidence = self._calculate_confidence(all_checks)
        recommendations = self._generate_recommendations(
            applicability, affected_environments, all_checks
        )
        
        return EnvironmentValidationResult(
            applicability=applicability,
            confidence=confidence,
            checks_performed=all_checks,
            affected_environments=affected_environments,
            recommendations=recommendations,
            details=self._generate_details(all_checks, affected_environments)
        )
    
    def _check_environment(self, vulnerability_report: Dict[str, Any],
                          env_config: EnvironmentConfig) -> List[ApplicabilityCheck]:
        """Check if vulnerability applies to specific environment."""
        checks = []
        
        # Check 1: Network accessibility
        checks.append(self._check_network_accessibility(vulnerability_report, env_config))
        
        # Check 2: Feature flags
        checks.append(self._check_feature_flags(vulnerability_report, env_config))
        
        # Check 3: Access controls
        checks.append(self._check_access_controls(vulnerability_report, env_config))
        
        # Check 4: Deployed services
        checks.append(self._check_deployed_services(vulnerability_report, env_config))
        
        # Check 5: Authentication requirements
        checks.append(self._check_authentication(vulnerability_report, env_config))
        
        return checks
    
    def _check_network_accessibility(self, vulnerability_report: Dict[str, Any],
                                    env_config: EnvironmentConfig) -> ApplicabilityCheck:
        """Check if vulnerable endpoint is network accessible."""
        affected_endpoint = vulnerability_report.get('affected_endpoint', '')
        
        # Check if endpoint is in public endpoints list
        is_public = any(
            endpoint in affected_endpoint
            for endpoint in env_config.public_endpoints
        )
        
        if is_public:
            return ApplicabilityCheck(
                check_name="network_accessibility",
                applicable=True,
                reason="Vulnerable endpoint is publicly accessible",
                confidence=0.9
            )
        else:
            return ApplicabilityCheck(
                check_name="network_accessibility",
                applicable=False,
                reason="Vulnerable endpoint is not publicly accessible",
                confidence=0.7
            )
    
    def _check_feature_flags(self, vulnerability_report: Dict[str, Any],
                            env_config: EnvironmentConfig) -> ApplicabilityCheck:
        """Check if vulnerable feature is enabled."""
        affected_feature = vulnerability_report.get('affected_feature', '')
        
        if not affected_feature:
            return ApplicabilityCheck(
                check_name="feature_flags",
                applicable=True,
                reason="No feature flag specified",
                confidence=0.5
            )
        
        # Check if feature is enabled
        is_enabled = env_config.feature_flags.get(affected_feature, True)
        
        if is_enabled:
            return ApplicabilityCheck(
                check_name="feature_flags",
                applicable=True,
                reason=f"Feature '{affected_feature}' is enabled",
                confidence=0.9
            )
        else:
            return ApplicabilityCheck(
                check_name="feature_flags",
                applicable=False,
                reason=f"Feature '{affected_feature}' is disabled",
                confidence=0.95
            )
    
    def _check_access_controls(self, vulnerability_report: Dict[str, Any],
                              env_config: EnvironmentConfig) -> ApplicabilityCheck:
        """Check if access controls prevent exploitation."""
        affected_endpoint = vulnerability_report.get('affected_endpoint', '')
        required_auth = vulnerability_report.get('requires_authentication', False)
        
        # Get access level for endpoint
        access_level = env_config.access_controls.get(
            affected_endpoint,
            AccessLevel.PUBLIC if not required_auth else AccessLevel.AUTHENTICATED
        )
        
        if access_level == AccessLevel.PUBLIC:
            return ApplicabilityCheck(
                check_name="access_controls",
                applicable=True,
                reason="Endpoint is publicly accessible without authentication",
                confidence=0.9
            )
        elif access_level == AccessLevel.AUTHENTICATED and not required_auth:
            return ApplicabilityCheck(
                check_name="access_controls",
                applicable=True,
                reason="Endpoint requires authentication but vulnerability doesn't",
                confidence=0.6
            )
        else:
            return ApplicabilityCheck(
                check_name="access_controls",
                applicable=False,
                reason=f"Endpoint protected by {access_level.value} access control",
                confidence=0.7
            )
    
    def _check_deployed_services(self, vulnerability_report: Dict[str, Any],
                                env_config: EnvironmentConfig) -> ApplicabilityCheck:
        """Check if vulnerable service is deployed."""
        affected_service = vulnerability_report.get('affected_service', '')
        
        if not affected_service:
            return ApplicabilityCheck(
                check_name="deployed_services",
                applicable=True,
                reason="No specific service mentioned",
                confidence=0.5
            )
        
        is_deployed = affected_service in env_config.deployed_services
        
        if is_deployed:
            return ApplicabilityCheck(
                check_name="deployed_services",
                applicable=True,
                reason=f"Service '{affected_service}' is deployed",
                confidence=0.95
            )
        else:
            return ApplicabilityCheck(
                check_name="deployed_services",
                applicable=False,
                reason=f"Service '{affected_service}' is not deployed",
                confidence=0.95
            )
    
    def _check_authentication(self, vulnerability_report: Dict[str, Any],
                             env_config: EnvironmentConfig) -> ApplicabilityCheck:
        """Check authentication requirements."""
        requires_auth = vulnerability_report.get('requires_authentication', False)
        
        if not requires_auth and env_config.authentication_required:
            return ApplicabilityCheck(
                check_name="authentication",
                applicable=False,
                reason="Environment requires authentication but vulnerability doesn't need it",
                confidence=0.6
            )
        else:
            return ApplicabilityCheck(
                check_name="authentication",
                applicable=True,
                reason="Authentication requirements match",
                confidence=0.7
            )
    
    def _calculate_applicability(self, checks: List[ApplicabilityCheck]) -> ApplicabilityLevel:
        """Calculate overall applicability from checks."""
        if not checks:
            return ApplicabilityLevel.UNKNOWN
        
        applicable_count = sum(1 for check in checks if check.applicable)
        total_checks = len(checks)
        
        ratio = applicable_count / total_checks
        
        if ratio >= 0.8:
            return ApplicabilityLevel.APPLICABLE
        elif ratio >= 0.4:
            return ApplicabilityLevel.PARTIALLY_APPLICABLE
        else:
            return ApplicabilityLevel.NOT_APPLICABLE
    
    def _calculate_confidence(self, checks: List[ApplicabilityCheck]) -> float:
        """Calculate confidence in applicability assessment."""
        if not checks:
            return 0.0
        
        # Average confidence of all checks
        return sum(check.confidence for check in checks) / len(checks)
    
    def _generate_recommendations(self, applicability: ApplicabilityLevel,
                                 affected_environments: List[EnvironmentType],
                                 checks: List[ApplicabilityCheck]) -> List[str]:
        """Generate recommendations based on validation results."""
        recommendations = []
        
        if applicability == ApplicabilityLevel.NOT_APPLICABLE:
            recommendations.append(
                "Vulnerability does not apply to current environment configuration"
            )
            recommendations.append(
                "Consider marking as false positive or not applicable"
            )
        elif applicability == ApplicabilityLevel.PARTIALLY_APPLICABLE:
            recommendations.append(
                "Vulnerability partially applies - review specific conditions"
            )
            # Add specific recommendations based on failed checks
            for check in checks:
                if not check.applicable:
                    recommendations.append(f"Note: {check.reason}")
        else:
            recommendations.append(
                "Vulnerability applies to environment - prioritize remediation"
            )
            if EnvironmentType.PRODUCTION in affected_environments:
                recommendations.append(
                    "⚠️ CRITICAL: Production environment is affected"
                )
        
        return recommendations
    
    def _generate_details(self, checks: List[ApplicabilityCheck],
                         affected_environments: List[EnvironmentType]) -> str:
        """Generate detailed explanation of validation results."""
        details = []
        
        details.append(f"Performed {len(checks)} environment checks")
        
        applicable_checks = [c for c in checks if c.applicable]
        details.append(f"{len(applicable_checks)}/{len(checks)} checks indicate applicability")
        
        if affected_environments:
            env_names = [e.value for e in affected_environments]
            details.append(f"Affected environments: {', '.join(env_names)}")
        
        return ". ".join(details)

