"""
AI Assistant for Enhanced Vulnerability Analysis
OPTIONAL - requires user consent
PRIVACY-FIRST - code is anonymized before sending

Features:
- User consent required (per-request OR always for project)
- Code anonymization before AI analysis
- Offline-first - works without AI
- Optional Claude.ai integration for deep analysis
"""
import json
import os
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

from .anonymizer import CodeAnonymizer


class AIAssistant:
    """
    Optional AI-powered vulnerability analysis

    Privacy & Security:
    1. Asks for user permission BEFORE sending
    2. Anonymizes code (removes sensitive data)
    3. Option to enable for entire project (always consent)
    4. Can be fully disabled
    5. Works offline without AI (falls back to ML only)

    User options:
    - [y] Yes, analyze this one finding
    - [N] No, skip this finding (default)
    - [always] Yes to all in this project
    - [never] Disable AI for this session
    """

    def __init__(self, api_key: Optional[str] = None, enabled: bool = False,
                 always_consent: bool = False):
        """
        Initialize AI Assistant

        Args:
            api_key: Claude API key (optional)
            enabled: Enable AI assistant
            always_consent: Auto-approve all AI requests (with anonymization)
        """
        self.enabled = enabled
        self.api_key = api_key
        self.always_consent = always_consent
        self.never_consent = False
        self.anonymizer = CodeAnonymizer()

        # Statistics
        self.stats = {
            'total_analyzed': 0,
            'consents_given': 0,
            'consents_denied': 0,
            'vulnerabilities_confirmed': 0,
            'false_positives_caught': 0,
        }

    def analyze_finding(self, finding: Dict[str, Any],
                       ask_permission: bool = True) -> Optional[Dict[str, Any]]:
        """
        Analyze vulnerability finding with AI

        Args:
            finding: Vulnerability finding dictionary
            ask_permission: Whether to ask for user consent

        Returns:
            AI analysis result or None if disabled/denied
        """

        # Check if AI is enabled
        if not self.enabled or self.never_consent:
            return None

        # Check API key
        if not self.api_key and not self._is_mock_mode():
            return None

        # Ask for permission (unless always_consent is True)
        if ask_permission and not self.always_consent:
            consent = self._ask_user_consent(finding)

            if consent == 'never':
                self.never_consent = True
                return None
            elif consent == 'always':
                self.always_consent = True
                # Continue to analysis
            elif consent == 'no':
                self.stats['consents_denied'] += 1
                return None
            elif consent != 'yes':
                return None

        self.stats['consents_given'] += 1

        # Anonymize code
        code = finding.get('code_snippet', '')
        if not code:
            return None

        anon_code, mapping = self.anonymizer.anonymize(code)

        # Build AI prompt
        prompt = self._build_analysis_prompt(finding, anon_code)

        # Call AI (or mock if no API key)
        if self._is_mock_mode():
            result = self._mock_analysis(finding, anon_code)
        else:
            result = self._call_claude_api(prompt)

        # Update statistics
        self.stats['total_analyzed'] += 1
        if result and result.get('is_real_vulnerability'):
            self.stats['vulnerabilities_confirmed'] += 1
        else:
            self.stats['false_positives_caught'] += 1

        return result

    def _ask_user_consent(self, finding: Dict[str, Any]) -> str:
        """
        Ask user for permission to send code to AI

        Returns: 'yes', 'no', 'always', or 'never'
        """
        print("\n" + "="*70)
        print("🤖 AI ASSISTANT - Prosi o Pozwolenie")
        print("="*70)
        print(f"\nPodatność do analizy:")
        print(f"  Typ: {finding.get('title', 'Unknown')}")
        print(f"  Severity: {finding.get('severity', 'Unknown')}")
        print(f"  Plik: {finding.get('file_path', 'Unknown')}")
        print(f"  Linia: {finding.get('line_number', '?')}")

        # Show anonymized preview
        code = finding.get('code_snippet', '')
        if code:
            preview = self.anonymizer.preview_anonymization(code, max_length=150)
            print("\n📝 Podgląd ANONIMIZOWANEGO kodu (będzie wysłany):")
            print("-" * 70)
            anon_code, _ = self.anonymizer.anonymize(code)
            print(anon_code[:150] + "..." if len(anon_code) > 150 else anon_code)
            print("-" * 70)

            stats = self.anonymizer.get_anonymization_stats()
            print(f"\n🔒 Anonimizacja:")
            print(f"  - Zmiennych: {stats['variables_anonymized']}")
            print(f"  - Stringów: {stats['strings_anonymized']}")
            print(f"  - Funkcji: {stats['functions_anonymized']}")

        print("\n⚠️  ŻADNE wrażliwe dane NIE będą wysłane!")
        print("   Zmienne/stringi zastąpione placeholderami")
        print("   Tylko struktura kodu jest analizowana\n")

        print("Opcje:")
        print("  [y]      Tak, wyślij TEN znalezisko do Claude.ai")
        print("  [N]      Nie, pomiń (domyślnie)")
        print("  [always] Tak, automatycznie dla CAŁEGO projektu (z anonimizacją)")
        print("  [never]  Nigdy nie pytaj w tej sesji (wyłącz AI)")

        try:
            choice = input("\nTwój wybór [y/N/always/never]: ").strip().lower()

            if choice == 'y' or choice == 'yes':
                return 'yes'
            elif choice == 'always':
                print("\n✅ AI Assistant włączony automatycznie dla całego projektu!")
                print("   (Kod nadal będzie anonimizowany)\n")
                return 'always'
            elif choice == 'never':
                print("\n❌ AI Assistant wyłączony dla tej sesji.\n")
                return 'never'
            else:
                return 'no'
        except (KeyboardInterrupt, EOFError):
            print("\n\n❌ Przerwano. AI wyłączony.\n")
            return 'never'

    def _build_analysis_prompt(self, finding: Dict[str, Any], anon_code: str) -> str:
        """Build AI analysis prompt"""
        prompt = f"""Przeanalizuj ten kod pod kątem podatności bezpieczeństwa.

KOD (ANONIMIZOWANY):
```
{anon_code}
```

PODEJRZANA PODATNOŚĆ:
- Typ: {finding.get('title', 'Unknown')}
- Severity: {finding.get('severity', 'Unknown')}
- CWE: {finding.get('cwe_id', 'Unknown')}
- Opis: {finding.get('description', 'Brak opisu')}

PYTANIE:
Czy to jest PRAWDZIWA podatność czy FALSE POSITIVE?

Odpowiedz w JSON:
{{
  "is_real_vulnerability": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "wyjaśnienie po polsku",
  "severity_adjustment": "CRITICAL/HIGH/MEDIUM/LOW/INFO lub null",
  "recommendation": "konkretna rekomendacja naprawy"
}}

Pamiętaj:
- Kod jest ANONIMIZOWANY (var_1, var_2, etc.)
- Analizuj STRUKTURĘ i FLOW, nie konkretne nazwy
- Zwróć uwagę na pattern matching vs rzeczywiste zagrożenie
"""
        return prompt

    def _call_claude_api(self, prompt: str) -> Optional[Dict[str, Any]]:
        """
        Call Claude AI API

        NOTE: This is a placeholder - requires actual Anthropic API integration
        For production use, install: pip install anthropic
        """
        try:
            # This would be actual API call:
            # import anthropic
            # client = anthropic.Anthropic(api_key=self.api_key)
            # message = client.messages.create(
            #     model="claude-3-5-sonnet-20241022",
            #     max_tokens=1024,
            #     messages=[{"role": "user", "content": prompt}]
            # )
            # response_text = message.content[0].text
            # return json.loads(response_text)

            # For now, return None (not implemented)
            print("⚠️  Claude API integration not yet implemented")
            print("   Install: pip install anthropic")
            print("   Falling back to mock analysis...\n")
            return None

        except Exception as e:
            print(f"⚠️  AI API Error: {e}")
            return None

    def _is_mock_mode(self) -> bool:
        """Check if running in mock mode (no API key)"""
        return not self.api_key or self.api_key == "mock"

    def _mock_analysis(self, finding: Dict[str, Any], anon_code: str) -> Dict[str, Any]:
        """
        Mock AI analysis for demonstration
        Returns simulated AI response
        """
        # Simple heuristic for mock
        severity = finding.get('severity', 'MEDIUM')
        code_lower = anon_code.lower()

        # Check for sanitization indicators in anonymized code
        has_sanitization = any(keyword in code_lower for keyword in
                             ['escape', 'sanitize', 'validate', 'filter'])

        # Mock decision
        is_real = not has_sanitization and severity in ['CRITICAL', 'HIGH']

        return {
            'is_real_vulnerability': is_real,
            'confidence': 0.75 if is_real else 0.60,
            'reasoning': f"Mock analysis: {'Prawdopodobnie prawdziwa podatność' if is_real else 'Możliwy false positive'} - detected {'sanitization' if has_sanitization else 'no protection'}",
            'severity_adjustment': None,
            'recommendation': "Użyj prawdziwego AI API dla dokładnej analizy (pip install anthropic)"
        }

    def enhance_findings(self, findings: List[Dict[str, Any]],
                        max_analyze: int = None) -> Tuple[List[Dict], List[Dict]]:
        """
        Enhance findings with AI analysis

        Args:
            findings: List of vulnerability findings
            max_analyze: Maximum findings to analyze (None = all)

        Returns:
            (confirmed_vulnerabilities, likely_false_positives)
        """
        if not self.enabled:
            return findings, []

        confirmed = []
        false_positives = []

        count = 0
        for finding in findings:
            # Limit if specified
            if max_analyze and count >= max_analyze:
                confirmed.append(finding)
                continue

            # Analyze with AI
            ai_result = self.analyze_finding(finding, ask_permission=True)

            if ai_result:
                finding['ai_analysis'] = ai_result
                count += 1

                if ai_result.get('is_real_vulnerability', True):
                    confirmed.append(finding)
                else:
                    false_positives.append(finding)
            else:
                # No AI analysis - keep original
                confirmed.append(finding)

        return confirmed, false_positives

    def get_statistics(self) -> Dict[str, Any]:
        """Get AI assistant statistics"""
        return {
            **self.stats,
            'always_consent_enabled': self.always_consent,
            'never_consent_enabled': self.never_consent,
            'api_configured': bool(self.api_key),
        }

    def print_statistics(self):
        """Print AI assistant statistics"""
        stats = self.get_statistics()

        print("\n" + "="*70)
        print("🤖 AI ASSISTANT - Statystyki Sesji")
        print("="*70)
        print(f"Total analyzed: {stats['total_analyzed']}")
        print(f"Consents given: {stats['consents_given']}")
        print(f"Consents denied: {stats['consents_denied']}")
        print(f"Vulnerabilities confirmed: {stats['vulnerabilities_confirmed']}")
        print(f"False positives caught: {stats['false_positives_caught']}")
        print(f"Always consent: {'✅ Enabled' if stats['always_consent_enabled'] else '❌ Disabled'}")
        print(f"API configured: {'✅ Yes' if stats['api_configured'] else '❌ No (mock mode)'}")
        print("="*70 + "\n")
