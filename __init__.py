"""
Snake Containment - Security analysis tool for CI/CD pipelines
"""

__version__ = "0.1.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"

from .core.scanner import BaseScanner, ScanResult, Finding, Severity
from .core.secrets import SecretsScanner

__all__ = [
    "BaseScanner",
    "ScanResult", 
    "Finding",
    "Severity",
    "SecretsScanner",
]