# System Audytu Bezpieczeństwa Kodu Aplikacji Webowych

Kompleksowy system do automatycznego audytu bezpieczeństwa kodu źródłowego aplikacji webowych. Wykrywa podatności OWASP Top 10, hardcoded secrets, oraz problemy z zależnościami.

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## 🚀 Funkcje

### Wykrywanie Podatności Webowych
- **SQL Injection** (CWE-89) - wykrywa niebezpieczne konkatenacje SQL
- **XSS** (CWE-79) - identyfikuje niebezpieczne renderowanie danych
- **Command Injection** (CWE-78) - wykrywa wykonywanie poleceń z user input
- **Path Traversal** (CWE-22) - identyfikuje zagrożenia traversal ścieżek
- **SSRF** (CWE-918) - wykrywa podatności Server-Side Request Forgery
- **XXE** (CWE-611) - identyfikuje problemy z XML parsers
- **CSRF** (CWE-352) - sprawdza ochronę przed atakami CSRF
- **Insecure Deserialization** (CWE-502) - wykrywa niebezpieczną deserializację
- **Weak Cryptography** (CWE-327) - identyfikuje słabe algorytmy kryptograficzne
- **Hardcoded Credentials** (CWE-798) - wykrywa hardcoded hasła i klucze

### Wykrywanie Sekretów
- AWS Access Keys & Secret Keys
- GitHub Tokens (PAT, OAuth)
- Google API Keys
- Slack Tokens & Webhooks
- Stripe API Keys
- Database Connection Strings (PostgreSQL, MySQL, MongoDB)
- Private Keys (RSA, SSH, PGP)
- JWT Tokens
- SendGrid, Twilio, MailChimp API Keys
- Generic API keys, passwords, tokens

### Analiza Zależności
- Wykrywanie znanych podatności w pakietach NPM, Python, PHP
- Identyfikacja nieprzypietych wersji (wildcards)
- Ostrzeżenia o przestarzałych bibliotekach

### Raportowanie
- **JSON** - strukturyzowany format dla automatyzacji
- **HTML** - wizualny raport z podświetleniem kodu
- **SARIF** - standard dla integracji z GitHub, GitLab, Azure DevOps

## 📦 Instalacja

```bash
# Klonowanie repozytorium
git clone https://github.com/yourusername/security-audit-system.git
cd security-audit-system

# Opcjonalna instalacja zależności (system działa na czystym Pythonie 3.7+)
pip install -r requirements.txt
```

## 🎯 Szybki Start

```bash
# Skanowanie bieżącego katalogu
python3 security_audit_cli.py --path .

# Skanowanie z raportem HTML
python3 security_audit_cli.py --path . --output html --report report.html

# Skanowanie tylko określonych typów
python3 security_audit_cli.py --path . --scanners web,secrets

# Skanowanie z fail na critical issues (CI/CD)
python3 security_audit_cli.py --path . --fail-on critical
```

## 📖 Dokumentacja

- [Przewodnik Użytkowania](USAGE_GUIDE.md) - szczegółowa dokumentacja
- [README Security Audit](security_audit/README.md) - szczegóły techniczne

## 🔍 Przykład Użycia

```bash
$ python3 security_audit_cli.py --path examples --output html

╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║         Security Audit System for Web Applications           ║
║                         Version 1.0.0                         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

[*] Starting security audit of: /home/user/system/examples
[*] Registered scanners: 3
[!] Found 11 issue(s) in examples/vulnerable_code.py
[!] Found 14 issue(s) in examples/vulnerable_code.js
[!] Found 3 issue(s) in examples/package.json

[+] Scan completed in 0.02 seconds
[+] Files scanned: 3
[+] Total findings: 28

================================================================================
SCAN SUMMARY
================================================================================
Files scanned:     3
Lines scanned:     220
Scan duration:     0.02 seconds

Findings by severity:
  CRITICAL:        10
  HIGH:            6
  MEDIUM:          11
  LOW:             1
  INFO:            0
================================================================================
```

## 🛠️ Integracja CI/CD

### GitHub Actions

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Security Audit
        run: |
          python3 security_audit_cli.py --path . --output sarif --report security.sarif --fail-on high
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: security.sarif
```

### GitLab CI

```yaml
security_audit:
  stage: test
  script:
    - python3 security_audit_cli.py --path . --output sarif --report security.sarif --fail-on high
  artifacts:
    reports:
      sast: security.sarif
```

## 🎨 Wspierane Języki

- Python (.py)
- JavaScript/TypeScript (.js, .ts, .jsx, .tsx)
- PHP (.php)
- Java (.java)
- Ruby (.rb)
- Go (.go)
- C# (.cs)
- HTML (.html, .htm)
- XML (.xml)
- YAML/JSON (.yml, .yaml, .json)

## 📊 Formaty Raportów

### JSON Report
Strukturyzowany format idealny dla automatyzacji i integracji z innymi narzędziami.

### HTML Report
Wizualny, interaktywny raport z:
- Kolorowym podświetleniem według wagi
- Snippetami kodu z kontekstem
- Rekomendacjami naprawy
- Statystykami i podsumowaniem

### SARIF Report
Standard OASIS dla wyników statycznej analizy - integracja z:
- GitHub Security
- Azure DevOps
- GitLab Security Dashboard
- SonarQube

## ⚙️ Konfiguracja

Stwórz `config.json` aby dostosować skanowanie:

```json
{
  "scan_options": {
    "max_file_size_mb": 10,
    "excluded_dirs": [".git", "node_modules", "venv"],
    "included_extensions": [".py", ".js", ".php"]
  },
  "scanners": {
    "web_vulnerabilities": {
      "enabled": true,
      "checks": {
        "sql_injection": true,
        "xss": true,
        "command_injection": true
      }
    },
    "secrets_detector": {
      "enabled": true
    },
    "dependency_scanner": {
      "enabled": true,
      "severity_threshold": "MEDIUM"
    }
  }
}
```

Użyj: `python3 security_audit_cli.py --path . --config config.json`

## 🏗️ Architektura

```
security-audit-system/
├── security_audit/
│   ├── core/
│   │   ├── engine.py          # Główny silnik audytu
│   │   ├── scanner.py         # Interfejs bazowy
│   │   └── config.py          # System konfiguracji
│   ├── scanners/
│   │   ├── web_vulnerabilities.py
│   │   ├── secrets_detector.py
│   │   └── dependency_scanner.py
│   └── reporters/
│       ├── json_reporter.py
│       ├── html_reporter.py
│       └── sarif_reporter.py
├── security_audit_cli.py      # CLI interface
└── examples/                   # Przykładowy podatny kod
```

## 🔐 Poziomy Wagi

| Poziom | Opis | Działanie |
|--------|------|-----------|
| **CRITICAL** | Krytyczne zagrożenia wymagające natychmiastowej akcji | Napraw ASAP |
| **HIGH** | Poważne podatności | Napraw w ciągu tygodnia |
| **MEDIUM** | Średnie zagrożenia | Zaplanuj naprawę |
| **LOW** | Niskie zagrożenia | Rozważ naprawę |
| **INFO** | Informacyjne / best practices | Dobra praktyka |

## 📝 Przykłady

W katalogu `examples/` znajdziesz przykładowy podatny kod:
- `vulnerable_code.py` - Python/Flask z podatnościami
- `vulnerable_code.js` - JavaScript/Node.js z podatnościami
- `package.json` - Przykład z podatnymi zależnościami

## 🤝 Wkład w Projekt

Contributions są mile widziane! Aby dodać nowy skaner lub poprawić istniejący:

1. Fork repozytorium
2. Stwórz branch (`git checkout -b feature/nowy-skaner`)
3. Commit zmian (`git commit -am 'Dodaj nowy skaner'`)
4. Push do brancha (`git push origin feature/nowy-skaner`)
5. Stwórz Pull Request

## ⚠️ Ograniczenia

- System wykrywa **potencjalne** podatności - wymaga weryfikacji
- Nie zastępuje manualnego security review
- Nie wykrywa błędów logiki biznesowej
- Baza podatności wymaga aktualizacji

## 📜 Licencja

MIT License - zobacz [LICENSE](LICENSE) dla szczegółów.

## 👤 Autor

Security Audit Team

## 🙏 Podziękowania

- OWASP za dokumentację Top 10
- MITRE za bazę CWE
- Społeczność open source za inspirację

---

**Uwaga**: Ten system jest narzędziem pomocniczym. Zawsze przeprowadzaj profesjonalny security audit przed wdrożeniem aplikacji produkcyjnej.
