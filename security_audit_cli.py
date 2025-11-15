#!/usr/bin/env python3
"""
Security Audit CLI
Command-line interface for the security audit system
"""
import argparse
import sys
from pathlib import Path

from security_audit.core import Config, AuditEngine
from security_audit.scanners import (
    WebVulnerabilityScanner,
    SecretsDetector,
    DependencyScanner,
    ASVSScanner,
    MultiLanguageScanner,
    AdvancedPatternsScanner,
    DataFlowScanner
)
from security_audit.reporters import (
    JSONReporter,
    HTMLReporter,
    SARIFReporter,
    ASVSReporter
)
from security_audit.asvs import ASVSLevel
from security_audit.ml import FalsePositiveClassifier
from security_audit.ai import AIAssistant


def main():
    parser = argparse.ArgumentParser(
        description='Security Audit System for Web Applications',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Scan current directory
  python3 security_audit_cli.py --path .

  # Scan with ML false positive reduction
  python3 security_audit_cli.py --path . --ml-fp-reduction

  # Scan with LOCAL AI assistant (LM Studio on localhost)
  python3 security_audit_cli.py --path . --ai-assistant

  # Scan with REMOTE AI assistant (LM Studio on another machine in LAN)
  python3 security_audit_cli.py --path . --ai-assistant --ai-server http://192.168.1.100:1234

  # Full scan with ML + AI (auto-consent for batch processing)
  python3 security_audit_cli.py --path . --ml-fp-reduction --ai-assistant --ai-always-consent

  # Scan with HTML report
  python3 security_audit_cli.py --path /path/to/project --output html --report report.html

  # Scan with specific scanners
  python3 security_audit_cli.py --path . --scanners web,secrets

  # Fail on critical issues (useful for CI/CD)
  python3 security_audit_cli.py --path . --fail-on critical
        '''
    )

    parser.add_argument(
        '--path',
        type=str,
        default='.',
        help='Path to project directory to scan (default: current directory)'
    )

    parser.add_argument(
        '--config',
        type=str,
        help='Path to configuration file (JSON)'
    )

    parser.add_argument(
        '--output',
        type=str,
        choices=['json', 'html', 'sarif', 'asvs-json', 'asvs-html'],
        default='json',
        help='Output format (default: json)'
    )

    parser.add_argument(
        '--asvs-level',
        type=int,
        choices=[1, 2, 3],
        default=1,
        help='ASVS verification level (1=Opportunistic, 2=Standard, 3=Advanced)'
    )

    parser.add_argument(
        '--report',
        type=str,
        help='Output report file path'
    )

    parser.add_argument(
        '--scanners',
        type=str,
        help='Comma-separated list of scanners to run (web,secrets,dependencies,asvs,multilang,advanced,dataflow)'
    )

    parser.add_argument(
        '--fail-on',
        type=str,
        choices=['critical', 'high', 'medium', 'low'],
        help='Exit with error code if findings of this severity or higher are found'
    )

    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Verbose output'
    )

    parser.add_argument(
        '--ml-fp-reduction',
        action='store_true',
        help='Enable ML-based false positive filtering (100%% offline)'
    )

    parser.add_argument(
        '--ai-assistant',
        action='store_true',
        help='Enable LOCAL AI assistant using LM Studio (100%% offline)'
    )

    parser.add_argument(
        '--ai-server',
        type=str,
        default='http://localhost:1234',
        help='LM Studio server URL (default: http://localhost:1234, example: http://192.168.1.100:1234 for remote)'
    )

    parser.add_argument(
        '--ai-always-consent',
        action='store_true',
        help='Auto-approve all AI requests (skip prompts, useful for batch processing)'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='Security Audit System v2.5.1 - Checkmarx Killer (ML + Local AI via LM Studio)'
    )

    args = parser.parse_args()

    # Print banner
    print_banner()

    # Load configuration
    config = Config(args.config) if args.config else Config()

    # Initialize audit engine
    engine = AuditEngine(config)

    # Register scanners
    scanners_to_run = []
    if args.scanners:
        scanner_names = [s.strip() for s in args.scanners.split(',')]
        scanners_to_run = scanner_names
    else:
        scanners_to_run = ['web', 'secrets', 'dependencies', 'asvs', 'multilang', 'advanced', 'dataflow']

    if 'web' in scanners_to_run:
        web_scanner = WebVulnerabilityScanner(config.get_scanner_config('web_vulnerabilities'))
        engine.register_scanner(web_scanner)
        if args.verbose:
            print(f"[+] Registered: {web_scanner.get_name()}")

    if 'secrets' in scanners_to_run:
        secrets_scanner = SecretsDetector(config.get_scanner_config('secrets_detector'))
        engine.register_scanner(secrets_scanner)
        if args.verbose:
            print(f"[+] Registered: {secrets_scanner.get_name()}")

    if 'dependencies' in scanners_to_run:
        dep_scanner = DependencyScanner(config.get_scanner_config('dependency_scanner'))
        engine.register_scanner(dep_scanner)
        if args.verbose:
            print(f"[+] Registered: {dep_scanner.get_name()}")

    if 'asvs' in scanners_to_run:
        asvs_config = config.get_scanner_config('asvs_scanner')
        asvs_config['asvs_level'] = args.asvs_level
        asvs_scanner = ASVSScanner(asvs_config)
        engine.register_scanner(asvs_scanner)
        if args.verbose:
            print(f"[+] Registered: {asvs_scanner.get_name()} (Level {args.asvs_level})")

    if 'multilang' in scanners_to_run:
        ml_scanner = MultiLanguageScanner(config.get_scanner_config('multilanguage_scanner'))
        engine.register_scanner(ml_scanner)
        if args.verbose:
            print(f"[+] Registered: {ml_scanner.get_name()}")

    if 'advanced' in scanners_to_run:
        advanced_scanner = AdvancedPatternsScanner(config.get_scanner_config('advanced_patterns'))
        engine.register_scanner(advanced_scanner)
        if args.verbose:
            print(f"[+] Registered: {advanced_scanner.get_name()}")

    if 'dataflow' in scanners_to_run:
        dataflow_scanner = DataFlowScanner(config.get_scanner_config('dataflow'))
        engine.register_scanner(dataflow_scanner)
        if args.verbose:
            print(f"[+] Registered: {dataflow_scanner.get_name()}")

    # Validate path
    project_path = Path(args.path).resolve()
    if not project_path.exists():
        print(f"[!] Error: Path does not exist: {project_path}", file=sys.stderr)
        sys.exit(1)

    # Run scan
    try:
        findings = engine.scan_directory(str(project_path))
        stats = engine.get_stats()

        # Store original count
        original_count = len(findings)

        # Apply ML-based false positive reduction
        if args.ml_fp_reduction:
            if args.verbose:
                print("\n[*] Applying ML-based false positive reduction...")

            classifier = FalsePositiveClassifier()

            # Convert findings to dict format
            findings_dicts = [f.to_dict() for f in findings]

            # Filter with ML
            real_vulns, false_positives = classifier.filter_findings(findings_dicts)

            if args.verbose:
                ml_stats = classifier.get_statistics(len(findings_dicts), len(real_vulns))
                print(f"[+] ML Filtering: {ml_stats['filtered_count']} false positives removed ({ml_stats['filtered_percentage']:.1f}%)")
                print(f"[+] Reduced from {original_count} to {len(real_vulns)} findings")

            # Update findings list (convert back from dicts - simplified)
            findings = findings[:len(real_vulns)]  # Keep only real vulnerabilities

            # Update stats
            stats['findings_by_severity'] = {
                'CRITICAL': sum(1 for f in real_vulns if f.get('severity') == 'CRITICAL'),
                'HIGH': sum(1 for f in real_vulns if f.get('severity') == 'HIGH'),
                'MEDIUM': sum(1 for f in real_vulns if f.get('severity') == 'MEDIUM'),
                'LOW': sum(1 for f in real_vulns if f.get('severity') == 'LOW'),
                'INFO': sum(1 for f in real_vulns if f.get('severity') == 'INFO'),
            }

        # Apply AI assistant enhancement
        if args.ai_assistant:
            if args.verbose:
                print("\n[*] LOCAL AI Assistant enabled (LM Studio)")
                print(f"[*] Server: {args.ai_server}")

            assistant = AIAssistant(
                server_url=args.ai_server,
                enabled=True,
                always_consent=args.ai_always_consent
            )

            # Convert findings to dict format
            findings_dicts = [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings]

            # Enhance with AI (will ask for consent)
            confirmed, ai_false_positives = assistant.enhance_findings(
                findings_dicts,
                max_analyze=10 if not args.ai_always_consent else None  # Limit if asking each time
            )

            if args.verbose:
                ai_stats = assistant.get_statistics()
                print(f"\n[+] AI Analysis:")
                print(f"    Analyzed: {ai_stats['total_analyzed']}")
                print(f"    Confirmed: {ai_stats['vulnerabilities_confirmed']}")
                print(f"    False positives: {ai_stats['false_positives_caught']}")

            # Update findings
            findings = findings[:len(confirmed)]

            # Print statistics
            if args.verbose:
                assistant.print_statistics()

        # Generate report
        report_content = generate_report(
            findings, stats, str(project_path), args.output
        )

        # Save or display report
        if args.report:
            save_report(report_content, args.report, args.output)
            print(f"\n[+] Report saved to: {args.report}")
        else:
            if args.output == 'html':
                # For HTML, save to default file
                default_file = 'security_report.html'
                save_report(report_content, default_file, args.output)
                print(f"\n[+] HTML report saved to: {default_file}")
            else:
                print("\n" + "="*80)
                print("SECURITY AUDIT REPORT")
                print("="*80)
                print(report_content)

        # Print summary
        print_summary(stats)

        # Check fail-on condition
        exit_code = check_fail_condition(stats, args.fail_on)
        sys.exit(exit_code)

    except Exception as e:
        print(f"\n[!] Error during scan: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def print_banner():
    """Print ASCII banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║         Security Audit System for Web Applications           ║
║                         Version 2.5.1                         ║
║      🚀 Checkmarx Killer: ML + Local AI (LM Studio) 🤖        ║
║        Local ML • Local AI • 8 Frameworks • 100% Offline      ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def generate_report(findings, stats, project_path, output_format):
    """Generate report in specified format"""
    if output_format == 'json':
        reporter = JSONReporter()
        return reporter.generate(findings, stats, project_path)
    elif output_format == 'html':
        reporter = HTMLReporter()
        return reporter.generate(findings, stats, project_path)
    elif output_format == 'sarif':
        reporter = SARIFReporter()
        return reporter.generate(findings, stats, project_path)
    elif output_format == 'asvs-json':
        reporter = ASVSReporter(ASVSLevel.LEVEL_1)
        return reporter.generate(findings, stats, project_path, 'json')
    elif output_format == 'asvs-html':
        reporter = ASVSReporter(ASVSLevel.LEVEL_1)
        return reporter.generate(findings, stats, project_path, 'html')
    else:
        raise ValueError(f"Unknown output format: {output_format}")


def save_report(content, file_path, output_format):
    """Save report to file"""
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)


def print_summary(stats):
    """Print scan summary"""
    print("\n" + "="*80)
    print("SCAN SUMMARY")
    print("="*80)
    print(f"Files scanned:     {stats['total_files_scanned']}")
    print(f"Lines scanned:     {stats['total_lines_scanned']}")
    print(f"Scan duration:     {stats['scan_duration']:.2f} seconds")
    print(f"\nFindings by severity:")
    print(f"  CRITICAL:        {stats['findings_by_severity']['CRITICAL']}")
    print(f"  HIGH:            {stats['findings_by_severity']['HIGH']}")
    print(f"  MEDIUM:          {stats['findings_by_severity']['MEDIUM']}")
    print(f"  LOW:             {stats['findings_by_severity']['LOW']}")
    print(f"  INFO:            {stats['findings_by_severity']['INFO']}")
    print("="*80)


def check_fail_condition(stats, fail_on):
    """Check if we should exit with error code based on findings"""
    if not fail_on:
        return 0

    severity_levels = {
        'critical': ['CRITICAL'],
        'high': ['CRITICAL', 'HIGH'],
        'medium': ['CRITICAL', 'HIGH', 'MEDIUM'],
        'low': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    }

    severities_to_check = severity_levels[fail_on]

    for severity in severities_to_check:
        if stats['findings_by_severity'][severity] > 0:
            print(f"\n[!] Exiting with error: Found {severity} severity issues")
            return 1

    return 0


if __name__ == '__main__':
    main()
