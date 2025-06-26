import click
import json
from pathlib import Path
from typing import List

from .core.secrets import SecretsScanner
from .core.ip_address import IpAddressScanner
from .core.comment import CommentScanner
from .core.scanner import ScanResult


@click.group()
@click.version_option()
def cli():
    """Snake Containment - Security analysis tool for CI/CD pipelines"""
    pass


@cli.command()
@click.argument('target_path', type=click.Path(exists=True))
@click.option('--format', '-f', 
              type=click.Choice(['text', 'json', 'sarif']), 
              default='text',
              help='Output format')
@click.option('--output', '-o', 
              type=click.Path(), 
              help='Output file (default: stdout)')
@click.option('--scanner', '-s',
              multiple=True,
              type=click.Choice(['secrets', 'ip_address']),
              default=['secrets'],
              help='Scanners to run')
def scan(target_path: str, format: str, output: str, scanner: List[str]):
    """Scan target path for security issues"""
    
    results = []
    
    # Run selected scanners
    if 'secrets' in scanner:
        click.echo("Running secrets scanner...")
        secrets_scanner = SecretsScanner()
        result = secrets_scanner.scan(target_path)
        results.append(result)
    
    if 'ip_address' in scanner:
        click.echo("Running IP address scanner...")
        ip_scanner = IpAddressScanner()
        result = ip_scanner.scan(target_path)
        results.append(result)

    if 'comment' in scanner:
        click.echo('Running Comment scanner...')
        comment_scanner = CommentScanner()
        result = comment_scanner.scan(target_path)
        results.append(result)
    
    # Format and output results
    if format == 'json':
        output_json(results, output)
    elif format == 'sarif':
        output_sarif(results, output)
    else:
        output_text(results, output)


def output_text(results: List[ScanResult], output_file: str = ''):
    """Output results in human-readable text format"""
    output_lines = []
    
    total_findings = sum(len(r.findings) for r in results)
    
    if total_findings == 0:
        output_lines.append("🎉 No security issues found!")
        output_lines.append("")
    else:
        output_lines.append(f"🔍 Snake Containment Security Scan Results")
        output_lines.append("=" * 50)
        output_lines.append("")
        
        # Summary
        total_critical = sum(r.critical_count for r in results)
        total_high = sum(r.high_count for r in results)
        total_medium = sum(r.medium_count for r in results)
        total_low = sum(r.low_count for r in results)
        
        output_lines.append(f"📊 Summary:")
        output_lines.append(f"  Critical: {total_critical}")
        output_lines.append(f"  High:     {total_high}")
        output_lines.append(f"  Medium:   {total_medium}")
        output_lines.append(f"  Low:      {total_low}")
        output_lines.append(f"  Total:    {total_findings}")
        output_lines.append("")
        
        # Detailed findings
        for result in results:
            if not result.findings:
                continue
                
            output_lines.append(f"🔎 {result.scanner.title()} Scanner Results:")
            output_lines.append("-" * 30)
            
            # Group by severity
            severity_groups = {}
            for finding in result.findings:
                if finding.severity not in severity_groups:
                    severity_groups[finding.severity] = []
                severity_groups[finding.severity].append(finding)
            
            # Output in severity order
            for severity in ['critical', 'high', 'medium', 'low']:
                if severity not in severity_groups:
                    continue
                
                severity_emoji = {
                    'critical': '🚨',
                    'high': '🔴',
                    'medium': '🟡',
                    'low': '🔵'
                }
                
                output_lines.append(f"\n{severity_emoji[severity]} {severity.upper()} Issues:")
                
                for finding in severity_groups[severity]:
                    output_lines.append(f"  📄 {finding.file_path}:{finding.line_number}")
                    output_lines.append(f"     {finding.title}")
                    output_lines.append(f"     {finding.description}")
                    if finding.code_snippet:
                        output_lines.append(f"     Code: {finding.code_snippet}")
                    if finding.recommendation:
                        output_lines.append(f"     💡 {finding.recommendation}")
                    output_lines.append("")
            
            output_lines.append("")
    
    # Write output
    content = "\n".join(output_lines)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(content)
        click.echo(f"Results written to {output_file}")
    else:
        click.echo(content)


def output_json(results: List[ScanResult], output_file: str = ''):
    """Output results in JSON format"""
    data = {
        "scan_results": [result.dict() for result in results],
        "summary": {
            "total_findings": sum(len(r.findings) for r in results),
            "critical": sum(r.critical_count for r in results),
            "high": sum(r.high_count for r in results),
            "medium": sum(r.medium_count for r in results),
            "low": sum(r.low_count for r in results),
        }
    }
    
    content = json.dumps(data, indent=2)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(content)
        click.echo(f"JSON results written to {output_file}")
    else:
        click.echo(content)


def output_sarif(results: List[ScanResult], output_file: str = ''):
    """Output results in SARIF format for GitHub integration"""
    # Basic SARIF structure - this could be expanded
    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": []
    }
    
    # Map our severity levels to SARIF levels
    severity_to_sarif_level = {
        "critical": "error",
        "high": "error", 
        "medium": "warning",
        "low": "note"
    }
    
    for result in results:
        run = {
            "tool": {
                "driver": {
                    "name": f"snake-containment-{result.scanner}",
                    "version": "0.1.0"
                }
            },
            "results": []
        }
        
        for finding in result.findings:
            sarif_level = severity_to_sarif_level.get(finding.severity.value, "warning")
            
            sarif_result = {
                "ruleId": f"{result.scanner}-{finding.title.lower().replace(' ', '-')}",
                "message": {"text": finding.description},
                "level": sarif_level,
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file_path},
                        "region": {"startLine": finding.line_number}
                    }
                }]
            }
            run["results"].append(sarif_result)
        
        sarif_data["runs"].append(run)
    
    content = json.dumps(sarif_data, indent=2)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(content)
        click.echo(f"SARIF results written to {output_file}")
    else:
        click.echo(content)


def main():
    """Entry point for the CLI"""
    cli()


if __name__ == '__main__':
    main()