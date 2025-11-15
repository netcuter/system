# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.0] - 2025-11-15

### Enhanced - Comprehensive Multi-Language Pattern Coverage
**Significantly improved detection accuracy across all frameworks:**

#### XXE (XML External Entity) - Enhanced Coverage
- Added Python lxml patterns (etree.parse, etree.fromstring)
- Added Python xml.etree patterns (parse, fromstring, XML)
- Added defusedxml check (import xml without defusedxml)
- Added PHP patterns (simplexml_load, DOMDocument)
- Added Node.js patterns (DOMParser, libxmljs)

#### ReDoS (Regular Expression DoS) - Comprehensive Patterns
- Nested quantifiers detection (Python, JavaScript, PHP)
- Alternation with quantifiers (a|ab)*
- Repetition followed by same character
- JavaScript regex literals and RegExp
- PHP preg_* functions
- Critical patterns (.*)*, (.+)+

#### Archive Extraction - Multi-Language Support
- Enhanced Python patterns (tarfile, zipfile, shutil)
- Added Java ZIP patterns (ZipEntry, ZipInputStream)
- Added Node.js patterns (extract-zip, unzipper, tar)
- Added PHP patterns (ZipArchive, PharData)
- Path traversal validation checks

#### TOCTOU Race Conditions - Extended Coverage
- All Python file check functions (exists, isfile, isdir, stat)
- PHP file functions (file_exists, is_file, is_readable)
- Java file operations (exists, Files.exists)
- Node.js synchronous checks (existsSync, statSync)

#### SQL Injection - Framework-Specific Patterns
- Django ORM (.raw, .extra with unsafe where)
- SQLAlchemy (execute, text with f-strings)
- PHP/MySQL (mysql_query, mysqli, WordPress $wpdb)
- Node.js (template literals, Sequelize)
- Java/JDBC (Statement, createQuery)

#### XSS (Cross-Site Scripting) - Advanced Detection
- JavaScript DOM (innerHTML, outerHTML, insertAdjacentHTML)
- React (dangerouslySetInnerHTML)
- Vue.js (v-html)
- Angular (innerHTML binding, bypassSecurityTrust*)
- Template engines (Handlebars, EJS, Jinja2, Django)
- PHP (echo, print, short tags with user input)
- Python (HttpResponse, render_template_string)
- Java/JSP (JSP expressions, servlet output)

### Added - New Vulnerability Categories

#### Server-Side Template Injection (SSTI) - CWE-94
- Flask render_template_string with user input
- Jinja2 Template() and from_string()
- Node.js template compilation (pug, jade, ejs, handlebars)
- Java Velocity and FreeMarker

#### Insecure Direct Object Reference (IDOR) - CWE-639
- Direct object access via user-controlled IDs
- SQL/ORM queries with user IDs
- File access with request parameters
- Missing authorization checks

#### API Security Issues - CWE-799
- Missing rate limiting on endpoints
- Mass assignment vulnerabilities
- Verbose error exposure

#### Enhanced Hardcoded Secrets Detection - CWE-798
- API keys and tokens (32+ char patterns)
- AWS Access Key IDs (AKIA...)
- Private keys (PEM format)
- Hardcoded passwords and secrets

### Statistics
- **Total new/enhanced patterns:** 100+ additional detection rules
- **Languages covered:** Python, PHP, JavaScript/TypeScript, Java, C#
- **Frameworks:** Django, Flask, SQLAlchemy, React, Vue, Angular, Node.js, Spring
- **Expected detection improvement:** 30-50% more vulnerabilities found

### Testing
- Validated against 8 industry-standard vulnerable applications
- Tested across multiple frameworks and languages
- Cross-framework compatibility verified

## [2.2.0] - 2025-11-15

### Added - Professional SAST Tool Patterns
**Integrated advanced patterns from Bandit, Semgrep, and CodeQL:**

- **HTTP Request Without Timeout** (CWE-400) - From Bandit B113
  - Detects requests.get/post without timeout parameter
  - Identifies httpx and urllib calls without timeout
  - Prevents indefinite hangs in network operations

- **Unsafe Archive Extraction** (CWE-22) - From Bandit B202
  - Detects tarfile.extractall() without validation
  - Identifies ZIP extraction path traversal risks
  - Prevents directory traversal attacks via archives

- **Jinja2 XSS Risks** (CWE-79) - From Bandit B701
  - Detects autoescape=False in Jinja2 Environment
  - Identifies missing autoescape parameter (defaults to False)
  - Prevents template XSS vulnerabilities

- **Advanced Shell Injection** (CWE-78) - From Bandit patterns
  - Detects subprocess with shell=True
  - Identifies os.system with formatted strings
  - Finds relative path usage (PATH manipulation)

- **TOCTOU Race Conditions** (CWE-362) - From CVE-2025 patterns
  - Detects check-then-use patterns (os.exists → open)
  - Identifies os.access before file operations
  - Prevents time-of-check-time-of-use vulnerabilities

- **Advanced Deserialization** (CWE-502)
  - Pickle from untrusted sources (stdin, request)
  - YAML load without SafeLoader
  - Marshal deserialization risks
  - Shelve with user-controlled paths

- **Regex DoS (ReDoS)** (CWE-1333)
  - Nested quantifiers detection
  - Catastrophic backtracking patterns
  - Performance testing recommendations

- **Integer Overflow** (CWE-190)
  - Unchecked int() conversions from user input
  - Range with user-controlled integers
  - Arithmetic operations without bounds checking

- **Insecure File Upload** (CWE-434) - From Semgrep patterns
  - File uploads without extension validation
  - Missing secure_filename() usage
  - Django/Flask file handling issues

- **XXE Advanced** (CWE-611)
  - XML parsers without resolve_entities=False
  - Minidom parsing user XML
  - SAX parser without security features

- **Advanced Cryptography** (CWE-327) - From Bandit
  - DES/RC2/RC4 weak ciphers
  - ECB mode detection
  - Weak random for cryptographic use
  - Insufficient entropy (< 16 bytes)

- **Advanced SQL Injection** (CWE-89) - From Semgrep
  - Django raw() with % formatting
  - RawSQL with concatenation
  - cursor.execute with .format()
  - SQL in f-strings

- **LDAP Injection** (CWE-90)
  - LDAP search with user input
  - Unvalidated LDAP filter construction

- **NoSQL Injection** (CWE-943)
  - MongoDB queries with user input
  - NoSQL where clause concatenation

- **Prototype Pollution** (CWE-1321) - JavaScript
  - Object.assign with user input
  - Spread operator with req.body/query
  - Direct __proto__ assignment

### Statistics
- **Total patterns added:** 15 new categories
- **Total vulnerability checks:** 35+ categories (was 20)
- **Detection improvement:** 64% more findings (50 → 82 vulnerabilities on test code)
- **Based on:** Bandit, Semgrep, CodeQL, and CVE-2025 patterns

## [2.1.0] - 2024-11-15

### Added
- **CWE Top 25 2024 Support** - Added 10 new vulnerability detection patterns based on latest CWE rankings
- **Code Injection Detection** (CWE-94) - Detects eval(), exec() usage with user input
- **Clickjacking Detection** (CWE-1021) - Identifies missing X-Frame-Options headers
- **IDOR/Authorization Flaws** (CWE-863) - Detects improper authorization and insecure direct object references
- **Information Disclosure** (CWE-200) - Identifies sensitive data leaks in logs and debug output
- **Resource Exhaustion/DoS** (CWE-400) - Detects unbounded loops, recursion, and missing rate limits
- **Mass Assignment Vulnerabilities** (CWE-915) - Identifies unsafe mass assignment from user input
- **JWT Security Issues** (CWE-347) - Detects weak secrets, disabled verification, and 'none' algorithm
- **Privilege Management Flaws** (CWE-269) - Identifies privilege escalation risks and overly permissive settings
- **Open Redirect Detection** (CWE-601) - Detects user-controlled redirect URLs
- **Server-Side Template Injection** (CWE-94) - Identifies SSTI vulnerabilities in template engines

### Changed
- Updated version badge from 2.0.0 to 2.1.0
- Added CWE Top 25 2024 badge to README files
- Enhanced documentation with new vulnerability patterns (both English and Polish)
- Improved scanner coverage from 10 to 20+ vulnerability types

### Statistics
- Total vulnerability patterns: 20+ categories
- Detection improvement: 47% more findings on test code (32 → 47 vulnerabilities)
- Based on: CWE Top 25 Most Dangerous Software Weaknesses 2024 (published November 19, 2024)

## [2.0.0] - 2024-11-14

### Added
- Initial comprehensive security audit system
- OWASP ASVS 4.0 compliance framework
- Multi-language support (10+ programming languages)
- 5 scanner types: Web, Secrets, Dependencies, ASVS, MultiLanguage
- Multiple report formats: JSON, HTML, SARIF, ASVS-JSON, ASVS-HTML
- CI/CD integration with GitHub Actions
- Bilingual documentation (English and Polish)
- MIT License
- Contributing guidelines
- Code of Conduct

### Supported Languages
- Python (Django, Flask, FastAPI)
- JavaScript/TypeScript (Node.js, React, Vue, Angular)
- PHP (Laravel, Symfony)
- Java (Spring, Jakarta EE)
- Ruby (Ruby on Rails)
- Go (Gin, Echo, Fiber)
- C# (ASP.NET, .NET Core)
- Rust (Actix, Rocket)
- Kotlin (Spring Boot, Ktor)
- Scala (Play Framework, Akka)
- Elixir (Phoenix)

[2.1.0]: https://github.com/netcuter/system/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/netcuter/system/releases/tag/v2.0.0
