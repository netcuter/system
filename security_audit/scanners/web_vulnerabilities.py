"""
Web application vulnerability scanner
Detects common OWASP Top 10 vulnerabilities
"""
import re
from typing import List, Dict, Any

from ..core.scanner import BaseScanner, Finding, Severity


class WebVulnerabilityScanner(BaseScanner):
    """Scanner for web application vulnerabilities"""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self._init_patterns()

    def get_name(self) -> str:
        return "Web Vulnerability Scanner"

    def get_description(self) -> str:
        return "Detects common web application vulnerabilities (OWASP Top 10)"

    def _init_patterns(self):
        """Initialize vulnerability detection patterns"""

        # SQL Injection patterns
        self.sql_injection_patterns = [
            # Direct SQL concatenation
            (r'(execute|exec|query|rawQuery)\s*\(\s*["\'].*?\+.*?["\']',
             'Direct string concatenation in SQL query'),
            (r'(execute|exec|query|rawQuery)\s*\(\s*f["\'].*?\{.*?\}.*?["\']',
             'F-string interpolation in SQL query'),
            (r'(SELECT|INSERT|UPDATE|DELETE|DROP).*?(\+|\.format|\%s)',
             'String formatting in SQL statement'),
            (r'cursor\.execute\s*\(\s*["\'].*?(\+|\.format|\%)',
             'Unsafe SQL execution in Python'),
            (r'db\.(query|exec|raw)\s*\(["\'].*?(\+|\$\{)',
             'Unsafe SQL query construction'),
        ]

        # XSS patterns
        self.xss_patterns = [
            # Unsafe HTML rendering
            (r'innerHTML\s*=\s*(?!["\']\s*["\']\s*$)',
             'Potentially unsafe innerHTML assignment'),
            (r'document\.write\s*\(',
             'Use of document.write (XSS risk)'),
            (r'dangerouslySetInnerHTML\s*=\s*\{\{',
             'Use of dangerouslySetInnerHTML in React'),
            (r'v-html\s*=',
             'Use of v-html in Vue.js (XSS risk)'),
            (r'\{\{\{.*?\}\}\}',
             'Unescaped template output (Handlebars/Mustache)'),
            (r'<%=\s*[^-]',
             'Unescaped output in ERB/EJS templates'),
            (r'echo\s+\$_(GET|POST|REQUEST|COOKIE)',
             'Direct output of user input in PHP'),
            (r'print\s*\(\s*request\.(GET|POST|args|form|cookies)',
             'Direct output of user input in Python'),
        ]

        # Command Injection patterns
        self.command_injection_patterns = [
            (r'(exec|system|shell_exec|passthru|popen)\s*\(\s*\$_(GET|POST|REQUEST)',
             'Command injection via user input (PHP)'),
            (r'(os\.system|os\.popen|subprocess\.call|subprocess\.run|eval)\s*\([^)]*?(request\.|input\()',
             'Command injection risk (Python)'),
            (r'child_process\.(exec|spawn)\s*\([^)]*?(req\.|process\.argv)',
             'Command injection risk (Node.js)'),
            (r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*?(request\.|getParameter)',
             'Command injection risk (Java)'),
        ]

        # Path Traversal patterns
        self.path_traversal_patterns = [
            (r'(open|file_get_contents|readfile|include|require)\s*\(\s*\$_(GET|POST|REQUEST)',
             'Path traversal risk (PHP)'),
            (r'(open|read)\s*\([^)]*?(request\.|input\()',
             'Path traversal risk (Python)'),
            (r'fs\.(readFile|readFileSync|createReadStream)\s*\([^)]*?(req\.|params)',
             'Path traversal risk (Node.js)'),
            (r'\.\.[\\/]',
             'Potential path traversal sequence'),
        ]

        # SSRF patterns
        self.ssrf_patterns = [
            (r'(requests\.get|requests\.post|urllib\.request|http\.request)\s*\([^)]*?(request\.|input\()',
             'SSRF risk - user-controlled URL (Python)'),
            (r'(axios|fetch|http\.get|http\.request)\s*\([^)]*?(req\.|params)',
             'SSRF risk - user-controlled URL (JavaScript)'),
            (r'(curl_exec|file_get_contents)\s*\(\s*\$_(GET|POST|REQUEST)',
             'SSRF risk - user-controlled URL (PHP)'),
        ]

        # XXE patterns
        self.xxe_patterns = [
            (r'DocumentBuilder.*?setFeature.*?false',
             'XML parser without XXE protection'),
            (r'XMLReader.*?setFeature.*?false',
             'XML reader without XXE protection'),
            (r'SAXParser.*?(?!setFeature)',
             'SAX parser without explicit XXE protection'),
            (r'etree\.XMLParser\s*\([^)]*?(resolve_entities\s*=\s*True|load_dtd\s*=\s*True)',
             'XML parser with dangerous settings'),
        ]

        # CSRF patterns
        self.csrf_patterns = [
            (r'@(app\.route|route)\s*\([^)]*?methods\s*=\s*\[[^]]*?["\']POST["\']',
             'POST endpoint without visible CSRF protection'),
            (r'app\.(post|put|delete)\s*\(',
             'State-changing endpoint without visible CSRF protection'),
        ]

        # Insecure Deserialization
        self.deserialization_patterns = [
            (r'pickle\.loads?\s*\(',
             'Use of pickle (insecure deserialization risk)'),
            (r'yaml\.load\s*\([^)]*?\)',
             'Use of yaml.load without SafeLoader'),
            (r'unserialize\s*\(',
             'Use of unserialize (PHP)'),
            (r'JSON\.parse\s*\([^)]*?(req\.|params)',
             'JSON parsing of user input without validation'),
        ]

        # Weak Cryptography
        self.weak_crypto_patterns = [
            (r'hashlib\.(md5|sha1)\s*\(',
             'Use of weak hashing algorithm (MD5/SHA1)'),
            (r'(md5|sha1)\s*\(',
             'Use of weak hashing algorithm'),
            (r'DES|RC4|RC2',
             'Use of weak encryption algorithm'),
            (r'random\s*\(',
             'Use of non-cryptographic random'),
        ]

        # Hardcoded Credentials
        self.hardcoded_creds_patterns = [
            (r'(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']',
             'Hardcoded password'),
            (r'(api_key|apikey|api-key)\s*=\s*["\'][^"\']+["\']',
             'Hardcoded API key'),
            (r'(secret|secret_key)\s*=\s*["\'][^"\']{8,}["\']',
             'Hardcoded secret'),
        ]

        # Insecure HTTP usage
        self.insecure_http_patterns = [
            (r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)',
             'Use of insecure HTTP protocol'),
        ]

    def scan(self, file_path: str, content: str, file_type: str) -> List[Finding]:
        """Scan file for web vulnerabilities"""
        findings = []
        lines = content.splitlines()

        # Check configuration for which checks to run
        checks = self.config.get("checks", {})

        if checks.get("sql_injection", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.sql_injection_patterns,
                "SQL Injection", Severity.CRITICAL,
                "Use parameterized queries or ORM. Never concatenate user input into SQL.",
                "CWE-89", "A03:2021 - Injection"
            ))

        if checks.get("xss", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.xss_patterns,
                "Cross-Site Scripting (XSS)", Severity.HIGH,
                "Escape all user-controlled data before rendering. Use secure templating.",
                "CWE-79", "A03:2021 - Injection"
            ))

        if checks.get("command_injection", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.command_injection_patterns,
                "Command Injection", Severity.CRITICAL,
                "Avoid executing shell commands with user input. Use safe APIs instead.",
                "CWE-78", "A03:2021 - Injection"
            ))

        if checks.get("path_traversal", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.path_traversal_patterns,
                "Path Traversal", Severity.HIGH,
                "Validate and sanitize file paths. Use allowlists for file access.",
                "CWE-22", "A01:2021 - Broken Access Control"
            ))

        if checks.get("ssrf", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.ssrf_patterns,
                "Server-Side Request Forgery (SSRF)", Severity.HIGH,
                "Validate and restrict URLs. Use allowlists for external requests.",
                "CWE-918", "A10:2021 - Server-Side Request Forgery"
            ))

        if checks.get("xxe", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.xxe_patterns,
                "XML External Entity (XXE)", Severity.HIGH,
                "Disable external entity processing in XML parsers.",
                "CWE-611", "A05:2021 - Security Misconfiguration"
            ))

        if checks.get("csrf", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.csrf_patterns,
                "Missing CSRF Protection", Severity.MEDIUM,
                "Implement CSRF tokens for state-changing operations.",
                "CWE-352", "A01:2021 - Broken Access Control"
            ))

        if checks.get("insecure_deserialization", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.deserialization_patterns,
                "Insecure Deserialization", Severity.HIGH,
                "Avoid deserializing untrusted data. Use safe formats like JSON.",
                "CWE-502", "A08:2021 - Software and Data Integrity Failures"
            ))

        if checks.get("weak_crypto", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.weak_crypto_patterns,
                "Weak Cryptography", Severity.MEDIUM,
                "Use strong cryptographic algorithms (e.g., SHA-256, AES-256).",
                "CWE-327", "A02:2021 - Cryptographic Failures"
            ))

        if checks.get("hardcoded_credentials", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.hardcoded_creds_patterns,
                "Hardcoded Credentials", Severity.CRITICAL,
                "Never hardcode credentials. Use environment variables or secure vaults.",
                "CWE-798", "A07:2021 - Identification and Authentication Failures"
            ))

        findings.extend(self._check_patterns(
            file_path, lines, self.insecure_http_patterns,
            "Insecure HTTP", Severity.LOW,
            "Use HTTPS for all external communications.",
            "CWE-319", "A02:2021 - Cryptographic Failures"
        ))

        return findings

    def _check_patterns(self, file_path: str, lines: List[str], patterns: List[tuple],
                       title: str, severity: Severity, recommendation: str,
                       cwe_id: str, owasp_category: str) -> List[Finding]:
        """Check content against patterns"""
        findings = []

        for line_num, line in enumerate(lines, start=1):
            for pattern, description in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    finding = Finding(
                        scanner=self.get_name(),
                        severity=severity,
                        title=title,
                        description=description,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_code_snippet(lines, line_num),
                        recommendation=recommendation,
                        cwe_id=cwe_id,
                        owasp_category=owasp_category
                    )
                    findings.append(finding)

        return findings

    def _get_code_snippet(self, lines: List[str], line_num: int, context: int = 2) -> str:
        """Get code snippet with context"""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        snippet_lines = []

        for i in range(start, end):
            prefix = ">>>" if i == line_num - 1 else "   "
            snippet_lines.append(f"{prefix} {i + 1:4d} | {lines[i]}")

        return "\n".join(snippet_lines)
