from abc import ABC, abstractmethod
from typing import List, Dict, Any
from pydantic import BaseModel
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """Represents a security finding from a scanner"""
    scanner: str
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int = 0
    code_snippet: str = ""
    recommendation: str = ""
    metadata: Dict[str, Any] = {}


class ScanResult(BaseModel):
    """Container for all findings from a scan"""
    scanner: str
    findings: List[Finding] = []
    scan_metadata: Dict[str, Any] = {}
    
    @property
    def critical_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.CRITICAL])
    
    @property
    def high_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.HIGH])
    
    @property
    def medium_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.MEDIUM])
    
    @property
    def low_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.LOW])


class BaseScanner(ABC):
    """Base class for all security scanners"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return the scanner name"""
        pass
    
    @abstractmethod
    def scan(self, target_path: str) -> ScanResult:
        """
        Perform security scan on the target path
        
        Args:
            target_path: Path to scan (file, directory, or repository)
            
        Returns:
            ScanResult containing all findings
        """
        pass
    
    def is_enabled(self) -> bool:
        """Check if this scanner is enabled in config"""
        return self.config.get(f"{self.name}_enabled", True)