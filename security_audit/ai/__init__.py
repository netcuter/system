"""
AI Assistant module
OPTIONAL - requires user consent
Code is anonymized before sending to external AI
"""

from .anonymizer import CodeAnonymizer
from .assistant import AIAssistant

__all__ = [
    'CodeAnonymizer',
    'AIAssistant'
]
