__version__ = "2.0.0"
__author__ = "Security Team"

# Main exports
from .orchestrator import Orchestrator
from .config_loader import ConfigLoader
from .models import Report, ValidationResult, Verdict, Severity

# Enhanced features
from .extractors import HTTPRequestExtractor, HTTPRequest
from .generators import PoCGenerator, ProofOfConcept

__all__ = [
    'Orchestrator',
    'ConfigLoader',
    'Report',
    'ValidationResult',
    'Verdict',
    'Severity',
    'HTTPRequestExtractor',
    'HTTPRequest',
    'PoCGenerator',
    'ProofOfConcept'
]

