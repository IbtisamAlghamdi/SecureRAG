"""
Input Sanitization & Channel Separation — Layer 1 of SecureRAG Defense
=======================================================================
The concept of "channel separation" is applied:

- Data Channel: What the user sends as content

- Command Channel: Static system instructions

A successful attack requires merging the two channels—this layer prevents this merging.
"""

import re
import base64
import html
import unicodedata
from typing import Tuple

# ── Critical injection patterns that must be sterilized
CRITICAL_INJECTION_PATTERNS = [
    # Direct injection in system instructions
    r"ignore\s+(all\s+)?(previous\s+|prior\s+)?instructions?",
    r"forget\s+(all\s+)?(your\s+)?instructions?",
    r"disregard\s+(all\s+)?instructions?",
    r"bypass\s+(security|filter|safety|restriction)",
    r"override\s+(all\s+)?(safety|security|instructions?)?",
    r"jailbreak",

    # Attempts to extract System Prompt
    r"reveal\s+(the\s+)?(system\s+prompt|your\s+instructions?)",
    r"(show|print|output|display)\s+(the\s+)?(system\s+prompt|initial\s+instructions?)",
    r"what\s+(is|are)\s+your\s+(system\s+prompt|instructions?|guidelines?)",

    # (Template Injection)
    r"\{\{.*?\}\}",          # Jinja2-style
    r"\$\{.*?\}",             # Shell/JS-style
    r"<%.*?%>",               # ASP/JSP-style
    r"<\?.*?\?>",             # PHP-style

    # Attempts to break Mistral's mold
    r"\[/?INST\]",
    r"<</?SYS>>",
    r"<s>\s*\[INST\]",
]

# Unicode normalization tables (to prevent attacks using similar characters) ─────────────────
UNICODE_LOOKALIKE_MAP = {
    'і': 'i', 'ο': 'o', 'а': 'a', 'е': 'e', 'ѕ': 's',
    'ţ': 't', 'ƅ': 'b', 'ƀ': 'b', 'ƍ': 'd', 'ƍ': 'd',
    '\u200b': '',  # Zero-width space
    '\u200c': '',  # Zero-width non-joiner
    '\u200d': '',  # Zero-width joiner
    '\u2060': '',  # Word joiner
    '\ufeff': '',  # BOM
}


def _normalize_unicode(text: str) -> str:
    """تطبيع Unicode ومنع هجمات الأحرف المشابهة (Homoglyph Attacks)"""
    # NFC normalization first
    text = unicodedata.normalize('NFC', text)
    # Replacing similar letters
    for fake_char, real_char in UNICODE_LOOKALIKE_MAP.items():
        text = text.replace(fake_char, real_char)
    # Delete control characters except for new lines.
    text = ''.join(c for c in text if unicodedata.category(c) != 'Cc' or c in '\n\r\t')
    return text


def _decode_base64_if_attack(text: str) -> Tuple[str, bool]:
    """
    Detecting and decrypting Base64 — whether the entire text is Base64

    or Base64 is embedded within a sentence (the most common pattern in real-world attacks).
    """
    ATTACK_KEYWORDS = [
        'ignore', 'bypass', 'jailbreak', 'system', 'instruction',
        'reveal', 'override', 'forget', 'admin', 'password',
        'unrestricted', 'disregard', 'prompt', 'credentials',
        'exploit', 'hack', 'root', 'execute', 'unlock'
    ]

    def _try_decode(b64_str: str) -> str:
        try:
            padding = 4 - len(b64_str) % 4
            if padding != 4:
                b64_str += '=' * padding
            decoded = base64.b64decode(b64_str, validate=False).decode('utf-8', errors='ignore')
            readable = sum(32 <= ord(c) <= 126 or c in '\n\r\t' for c in decoded)
            if readable / max(len(decoded), 1) > 0.80:
                return decoded
        except Exception:
            pass
        return ""

    # Case 1: The entire text is base64
    stripped = text.strip()
    if re.match(r'^[A-Za-z0-9+/=]{20,}$', stripped):
        decoded = _try_decode(stripped)
        if decoded and any(kw in decoded.lower() for kw in ATTACK_KEYWORDS):
            return f"[BASE64_DECODED] {decoded}", True

    # Case 2: base64 is included after keywords

    # Example: "Decode and execute this command: <base64>"
    embedded = re.findall(
        r'(?:decode|execute|respond|encoded|message|command|query)\s*(?:this|to)?\s*:?\s*([A-Za-z0-9+/=]{20,})',
        text, re.IGNORECASE
    )
    for candidate in embedded:
        decoded = _try_decode(candidate)
        if decoded and any(kw in decoded.lower() for kw in ATTACK_KEYWORDS):
            new_text = text.replace(candidate, f"[DECODED: {decoded}]")
            return f"[BASE64_DECODED] {new_text}", True

    # Case 3: أي base64 طويل في النص
    all_b64 = re.findall(r'[A-Za-z0-9+/]{30,}={0,2}', text)
    for candidate in all_b64:
        decoded = _try_decode(candidate)
        if decoded and any(kw in decoded.lower() for kw in ATTACK_KEYWORDS):
            new_text = text.replace(candidate, f"[DECODED: {decoded}]")
            return f"[BASE64_DECODED] {new_text}", True

    return text, False


def _decode_html_entities(text: str) -> str:
    """Decoding HTML entities to uncover hidden attacks"""
    return html.unescape(text)


def _remove_template_injections(text: str) -> str:
    """
    Removes Template Injection attempts targeting Mistral/Llama templates.

    This is a direct application of Channel Separation — preventing the user from modifying the system's help channel.
    """
    # إزالة محاولات كسر قوالب Mistral
    text = re.sub(r'\[/?INST\]', '[FILTERED]', text, flags=re.IGNORECASE)
    text = re.sub(r'<</?SYS>>', '[FILTERED]', text, flags=re.IGNORECASE)
    text = re.sub(r'<s>\s*\[', '[', text, flags=re.IGNORECASE)
    # إزالة Template Injection العام
    text = re.sub(r'\{\{.*?\}\}', '[FILTERED]', text, flags=re.DOTALL)
    text = re.sub(r'\$\{.*?\}',   '[FILTERED]', text, flags=re.DOTALL)
    return text


def sanitize_input(text: str) -> str:
    """
    Channel Separation Defense Line:

    Ensures that the input remains in the "data channel" and does not infiltrate the "command channel".

    """
    if not text or not text.strip():
        return text

    # ── Step 1: Unicode Normalization (Preventing Character-Similar Attacks) ──────────────────
    text = _normalize_unicode(text)

    # ── Step 2: Decompose HTML entities─────────────
    text = _decode_html_entities(text)

    # ── Step 3: Uncover and decode Base64 (then process the decoded content) ───────
    text, was_base64 = _decode_base64_if_attack(text)
    if was_base64:
      # Unpacked content requires additional sterilization
        text = f"[BASE64_DECODED] {text}"

    # ── Step 4: Remove Template Injection (Essential Channel Separation) ────
    text = _remove_template_injections(text)

    # ── Step 5: Sterilizing critical patterns
    for pattern in CRITICAL_INJECTION_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL):
            text = re.sub(pattern, "[MALICIOUS_INTENT_DETECTED]",
                          text, flags=re.IGNORECASE | re.DOTALL)

    # ── Step 6: Determine the query length (prevent context flooding)───────
    MAX_QUERY_LENGTH = 1500
    if len(text) > MAX_QUERY_LENGTH:
        text = text[:MAX_QUERY_LENGTH] + " [TRUNCATED_FOR_SECURITY]"

    return text.strip()


def get_sanitization_report(original: str, sanitized: str) -> dict:
    """Sterilization report for academic documentation"""
    return {
        "original_length":  len(original),
        "sanitized_length": len(sanitized),
        "was_modified":     original != sanitized,
        "was_truncated":    "[TRUNCATED_FOR_SECURITY]" in sanitized,
        "had_base64":       "[BASE64_DECODED]" in sanitized,
        "had_injection":    "[MALICIOUS_INTENT_DETECTED]" in sanitized,
        "had_template_inj": "[FILTERED]" in sanitized,
        "reduction_ratio":  round(1 - len(sanitized)/max(len(original), 1), 3),
    }
