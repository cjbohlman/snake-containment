import re
import math
from pathlib import Path
from typing import List
from collections import Counter

from .scanner import BaseScanner, ScanResult, Finding, Severity


class SecretsScanner(BaseScanner):
    """Scanner for detecting secrets and credentials in code"""
    
    # Regex patterns for common secrets
    SECRET_PATTERNS = {
        'aws_access_key': re.compile(r'AKIA[0-9A-Z]{16}'),
        'aws_secret_key': re.compile(r'[A-Za-z0-9/+=]{40}'),
        'github_token': re.compile(r'gh[ps]_[A-Za-z0-9]{36}'),
        'slack_token': re.compile(r'xox[baprs]-([0-9a-zA-Z]{10,48})'),
        'discord_webhook': re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'),
        'generic_api_key': re.compile(r'["\']?[a-zA-Z0-9_-]*[aA][pP][iI][_-]?[kK][eE][yY]["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{20,})["\']?'),
        'jwt_token': re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
        'private_key': re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),
    }
    
    @property
    def name(self) -> str:
        return "secrets"
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        
        counter = Counter(text)
        length = len(text)
        entropy = 0.0
        
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def is_high_entropy_string(self, text: str, min_length: int = 20, min_entropy: float = 4.5) -> bool:
        """Check if a string has high entropy (potentially a secret)"""
        if len(text) < min_length:
            return False
        
        # Remove common patterns that aren't secrets
        if any(pattern in text.lower() for pattern in ['lorem', 'ipsum', 'example', 'test', 'dummy']):
            return False
        
        return self.calculate_entropy(text) >= min_entropy
    
    def extract_potential_secrets(self, content: str) -> List[str]:
        """Extract strings that might be secrets based on entropy"""
        # Look for quoted strings and assignment values
        patterns = [
            r'["\']([A-Za-z0-9+/=_-]{20,})["\']',  # Quoted strings
            r'[:=]\s*([A-Za-z0-9+/=_-]{20,})(?:\s|$)',  # Assignment values
        ]
        
        candidates = []
        for pattern in patterns:
            matches = re.findall(pattern, content)
            candidates.extend(matches)
        
        # Filter by entropy
        return [s for s in candidates if self.is_high_entropy_string(s)]
    
    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a single file for secrets"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            # Skip files we can't read
            return findings
        
        lines = content.split('\n')
        
        # Check pattern-based secrets
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.HIGH,
                    title=f"Potential {secret_type.replace('_', ' ').title()} Found",
                    description=f"Detected pattern matching {secret_type}",
                    file_path=str(file_path),
                    line_number=line_num,
                    code_snippet=self._truncate_code_snippet(line_content.strip()),
                    recommendation=f"Remove the {secret_type} from source code and use environment variables or secure secret management",
                    metadata={"pattern": secret_type, "match": match.group()}
                ))
        
        # Check entropy-based secrets
        for i, line in enumerate(lines, 1):
            potential_secrets = self.extract_potential_secrets(line)
            for secret in potential_secrets:
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.MEDIUM,
                    title="High Entropy String Detected",
                    description=f"Found string with high entropy (possibly a secret): {secret[:20]}...",
                    file_path=str(file_path),
                    line_number=i,
                    code_snippet=self._truncate_code_snippet(line.strip()),
                    recommendation="Review this string - if it's a secret, move it to environment variables",
                    metadata={"entropy": self.calculate_entropy(secret), "string_length": len(secret)}
                ))
        
        return findings
    
    def scan(self, target_path: str) -> ScanResult:
        """Scan target path for secrets"""
        target = Path(target_path)
        all_findings = []
        
        if target.is_file():
            if self.should_scan_file(target):
                all_findings.extend(self.scan_file(target))
        elif target.is_dir():
            for file_path in target.rglob('*'):
                if file_path.is_file() and self.should_scan_file(file_path):
                    all_findings.extend(self.scan_file(file_path))
        
        return ScanResult(
            scanner=self.name,
            findings=all_findings,
            scan_metadata={
                "target_path": target_path,
                "files_scanned": len(set(f.file_path for f in all_findings)),
                "entropy_threshold": 4.5,
                "min_string_length": 20
            }
        )