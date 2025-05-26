from abc import ABC, abstractmethod
from typing import List, Dict, Any
from pydantic import BaseModel
from enum import Enum
from pathlib import Path


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
    
    # Common file extensions to scan
    SCANNABLE_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
        '.yml', '.yaml', '.json', '.xml', '.env', '.cfg', '.conf', '.ini',
        '.sh', '.bash', '.zsh', '.ps1', '.sql', '.md', '.txt'
    }
    
    # Files and directories to skip
    SKIP_PATTERNS = {
        '.git', '.svn', '.hg', 'node_modules', '__pycache__', '.pytest_cache',
        'venv', 'env', '.env', 'dist', 'build', '.next', '.nuxt'
    }

    def should_scan_file(self, file_path: Path) -> bool:
        """Determine if a file should be scanned"""
        # Check file extension
        if file_path.suffix.lower() not in self.SCANNABLE_EXTENSIONS:
            return False
        
        # Check if any parent directory should be skipped
        for part in file_path.parts:
            if part in self.SKIP_PATTERNS:
                return False
        
        # Check file size (skip very large files)
        try:
            if file_path.stat().st_size > 10 * 1024 * 1024:  # 10MB
                return False
        except OSError:
            return False
        
        return True
    
    def _truncate_code_snippet(self, code: str, max_length: int = 100) -> str:
        """Intelligently truncate code snippets for display"""
        if not code:
            return ""
        
        # If it's short enough, return as-is
        if len(code) <= max_length:
            return code
        
        # For very long lines (likely minified), show context around secrets
        # Try to find where the actual secret might be
        truncated = code[:max_length]
        
        # If we're in the middle of a word/token, try to end at a reasonable boundary
        if max_length < len(code):
            # Look for natural break points near the end
            for boundary in [' ', '"', "'", '=', ':', ';', ',', ')', '}', ']']:
                last_boundary = truncated.rfind(boundary)
                if last_boundary > max_length - 20:  # Within 20 chars of the end
                    truncated = code[:last_boundary + 1]
                    break
        
        return truncated + "..." if len(code) > len(truncated) else truncated