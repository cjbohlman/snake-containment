import re
from pathlib import Path
from typing import List

from .scanner import BaseScanner, ScanResult, Finding, Severity


class IpAddressScanner(BaseScanner):
    """Scanner for detecting IP addresses in code"""
    
    def __init__(self, config=None):
        super().__init__(config)
        
        # Compile patterns once for better performance
        private_ip_patterns = [
            r'192\.168\.\d{1,3}\.\d{1,3}',
            r'172\.1[6-9]\.\d{1,3}\.\d{1,3}',
            r'172\.2[0-9]\.\d{1,3}\.\d{1,3}',
            r'172\.3[0-1]\.\d{1,3}\.\d{1,3}',
            r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            r'127\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        ]
        
        # Combine all private IP patterns
        self.private_ip_pattern = re.compile('|'.join(f'({pattern})' for pattern in private_ip_patterns))
        
        # More precise localhost pattern (word boundaries)
        self.localhost_patterns = [
            re.compile(r'"[^"]*localhost[^"]*"', re.IGNORECASE),
            re.compile(r"'[^']*localhost[^']*'", re.IGNORECASE),
            re.compile(r'host\s*[=:]\s*"[^"]*localhost[^"]*"', re.IGNORECASE),
            re.compile(r"host\s*[=:]\s*'[^']*localhost[^']*'", re.IGNORECASE),
            re.compile(r'server\s*[=:]\s*"[^"]*localhost[^"]*"', re.IGNORECASE),
            re.compile(r"server\s*[=:]\s*'[^']*localhost[^']*'", re.IGNORECASE),
            re.compile(r'host\s*[=:]\s*localhost\b', re.IGNORECASE),
            re.compile(r'server\s*[=:]\s*localhost\b', re.IGNORECASE),
        ]

    @property
    def name(self) -> str:
        return "ip_address"
    
    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a single file for IP addresses"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            # Skip files we can't read (like secrets scanner does)
            return findings
        
        lines = content.split('\n')
        
        # Check for private IP addresses
        for line_num, line in enumerate(lines, 1):
            # Private IPs
            for match in self.private_ip_pattern.finditer(line):
                ip_address = match.group()
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.MEDIUM,
                    title="Private IP Address Found",
                    description=f"Private IP address detected: {ip_address}",
                    file_path=str(file_path),
                    line_number=line_num,
                    code_snippet=self._truncate_code_snippet(line.strip()),
                    recommendation="Consider using environment variables or configuration files for IP addresses",
                    metadata={"ip_address": ip_address, "ip_type": "private"}
                ))
            
            # Localhost references
            for pattern in self.localhost_patterns:
                for match in pattern.finditer(line):
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.LOW,
                        title="Localhost Reference Found",
                        description="Reference to localhost detected",
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=self._truncate_code_snippet(line.strip()),
                        recommendation="Ensure localhost references are intentional and not hardcoded for production",
                        metadata={"reference": "localhost"}
                ))
        
        return findings
    
    def scan(self, target_path: str) -> ScanResult:
        """Scan target path for IP addresses"""
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
                "target_path": target_path,  # Fixed typo
                "files_scanned": len(set(f.file_path for f in all_findings)),
                "patterns_used": ["private_ips", "localhost"]
            }
        )