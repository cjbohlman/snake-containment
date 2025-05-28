import re
from pathlib import Path
from typing import List

from .scanner import BaseScanner, ScanResult, Finding, Severity


class CommentScanner(BaseScanner):
    """Scanner for detecting security related todos in code"""
    
    def __init__(self, config=None):
        super().__init__(config)
        
        # Compile patterns once for better performance
        comment_patterns = [
            r'#.*?(?:TODO|FIXME|BUG|NOTE|HACK).*',
            r'//.*?(?:TODO|FIXME|NOTE|HACK|BUG).*',
            r'/\*.*?(?:TODO|FIXME|NOTE|HACK|BUG).*?\*/',
            r'<!--.*?(?:TODO|FIXME|NOTE|HACK|BUG).*?-->',
            r'""".*?(?:TODO|FIXME|NOTE|HACK|BUG).*?"""',
        ]
        
        # Combine all comment patterns
        self.comment_pattern = re.compile('|'.join(f'({pattern})' for pattern in comment_patterns), re.IGNORECASE | re.MULTILINE)

        self.security_keywords = {
            'auth', 'authentication', 'authorization', 'login', 'password', 'token',
            'security', 'secure', 'encryption', 'decrypt', 'hash', 'salt',
            'permission', 'access', 'privilege', 'vulnerability', 'exploit',
            'sanitize', 'validate', 'escape', 'xss', 'sql injection', 'csrf',
            'https', 'ssl', 'tls', 'certificate', 'secret', 'key', 'api key'
        }

    @property
    def name(self) -> str:
        return "comment"
    
    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a single file for comments"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            # Skip files we can't read
            return findings
        
        lines = content.split('\n')
        
        # Check for potentially vulnerable comments
        for line_num, line in enumerate(lines, 1):
            for match in self.comment_pattern.finditer(line):
                comment = match.group()
                if any(keyword in comment.lower() for keyword in self.security_keywords):
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.LOW,
                        title="Potential Security-Related Comment Found",
                        description=f"Potential Security-Related Comment: {comment.strip()[:50]}",
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=self._truncate_code_snippet(line.strip()),
                        recommendation="Consider reviewing this comment for potential security implications.",
                        metadata={"comment": comment}
                    ))
        
        return findings
    
    def scan(self, target_path: str) -> ScanResult:
        """Scan target path for comments"""
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
                "patterns_used": ["comment_patterns"]
            }
        )