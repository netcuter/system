# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
