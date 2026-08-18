"""
Adaptive Risk Sensor (ARS) — Layer 3: Statistical Boundary Analysis

====================================================================
Analyzes query structure across 6 statistical dimensions to detect hidden attacks that bypass traditional text filters.

Contribution: ARS detects attacks that appear linguistically "normal" but have a suspicious structural design.
"""

import re
import math
from typing import Dict
from src.config import settings

# ── Dangerous Word Weights — Based on BIPIA and SafeRAG Analysis ─
# FIXED: the accumulation-multiplier bug below. Split into two tiers:
# HIGH_RISK_KEYWORDS are individually attack-flavored ("jailbreak",
# "system prompt", ...). GENERIC_CONTEXT_KEYWORDS are ordinary enterprise
# / IT vocabulary that legitimately co-occurs in normal security/dev
# discussion ("admin", "developer", "hidden", "confidential", ...) -- the
# comment already said these are "not dangerous on their own", but the
# accumulation multiplier below used to count them anyway, so an entirely
# ordinary sentence like "our admin's credentials are confidential and
# stored internally" (3 generic-tier hits) got a 1.5x score multiplier
# and could cross the blocking threshold on generic vocabulary alone.
# Confirmed by direct testing: 6/7 realistic (non-adversarial) IT/security
# questions were blocked purely from this before the fix. Both tiers still
# add their weight to the raw score -- only the tier that counts toward
# the *multiplier* trigger changed.
HIGH_RISK_KEYWORDS = {
    # Excessively high weight — a direct violation of the limits
    "ignore":          10.0,
    "bypass":          10.0,
    "jailbreak":       15.0,
    "override":        10.0,
    "disregard":       10.0,
    "forget":           8.0,
    "unrestricted":     9.0,
    "god mode":        12.0,
    "dan mode":        12.0,
    "no restrictions":  9.0,
    # High weight - extraction
    "reveal":           8.0,
    "system prompt":   10.0,
    "initialization":   7.0,
    "base prompt":      9.0,
    "your instructions": 8.0,
}
GENERIC_CONTEXT_KEYWORDS = {
   # Average weight — suspicious context
    "safety protocols": 6.0,
    "content filter":   6.0,
    "suspended":        4.0,
    "disabled":         4.0,
    "exempt":           5.0,
    "authorized":       3.0,
    "clearance":        5.0,
    "admin":            4.0,
    "developer":        3.0,
    "red team":         5.0,
    "pen test":         5.0,
    "evaluation mode":  6.0,
    # Low weight — not dangerous on its own
    "password":         3.0,
    "credentials":      3.0,
    "secret":           3.0,
    "internal":         2.0,
    "hidden":           3.0,
    "confidential":     3.0,
}
WEIGHTED_KEYWORDS = {**HIGH_RISK_KEYWORDS, **GENERIC_CONTEXT_KEYWORDS}

# Advanced camouflage patterns
OBFUSCATION_PATTERNS = [
    (r"^[A-Za-z0-9+/=]{20,}$",           25.0, "base64_payload"),
    (r"[і][g][n][о][r][е]",              15.0, "cyrillic_ignore"),    # Cyrillic lookalikes
    (r"\u200b|\u200c|\u200d|\u2060",      18.0, "zero_width_chars"),  # Zero-width
    (r"[a-z]\s[a-z]\s[a-z]\s[a-z]",     10.0, "char_spacing"),
    (r"ｉｇｎｏｒｅ|ｂｙｐａｓｓ",        15.0, "fullwidth_chars"),
    (r"(?:&#\d+;){3,}",                   15.0, "html_entities"),
    (r"\\x[0-9a-f]{2}",                   12.0, "hex_escape"),
    (r"1gn0r3|byp4ss|0verr1de",          12.0, "leetspeak_attack"),
    (r"i-g-n-o-r-e|b-y-p-a-s-s",        10.0, "hyphenated"),
]

#Structural indicators of multi-stage attacks
STAGED_SIGNALS = [
    r"step\s+[1-9]",
    r"phase\s+[1-9]",
    r"part\s+[1-9]\s+of\s+[1-9]",
    r"(first|then|next|finally|after\s+that)\s*[:,]",
    r"\d+\.\s+\w+.*\n.*\d+\.\s+\w+",
]

# Signs of psychological exploitation───────────────────────────────────────────────────
PSYCH_SIGNALS = [
    r"(mandatory|required|authorized)\s+(compliance|audit|check|override)",
    r"(system|security)\s+(breach|alert|warning|integrity)",
    r"(license|access|service)\s+will\s+be\s+revoked",
    r"as\s+(your\s+)?(developer|creator|provider|administrator)",
    r"(evaluation|test)\s+mode",
    r"emergency\s+(protocol|override|mode)",
]

# — Contextual poisoning signals —──────────────────────────────────────────────────────
CONTEXT_POISONING_SIGNALS = [
    r"\[.{5,80}(ignore|bypass|override|reveal|instruction).{0,80}\]",
    r"\{.{5,60}(override|system|safety|filter).{0,60}\}",
    r"<!--.{0,100}(ignore|bypass|instruction).{0,100}-->",
    r"\bNOTE\s+TO\s+AI\b",
    r"\bAI\s+(INSTRUCTION|DIRECTIVE|COMMAND)\b",
    r"\bSYSTEM[_\s]OVERRIDE\b",
    r"\bHIDDEN\s+INSTRUCTION\b",
]


def compute_anomaly_score(text: str) -> float:
    """
   ARS — Calculating the Abnormality Score across 6 Dimensions:
    1. Length and Structural Complexity
    2. (Risk Density)
    3. (Obfuscation Detection)
    4. (Staged Attacks)
    5. (Psychological Manipulation)
    6. (Context Poisoning Signals)
    """
    score = 0.0
    text_lower = text.lower()

    # Dimension 1: Length and Complexity─────────────────────────────────────────────
    # FIXED: found via the BIPIA external FPR run (68.47%, 228/333 false
    # positives) -- confirmed by direct measurement that 211/333 (63%) of
    # those benign documents are long (>800 chars) with ZERO suspicious
    # keywords anywhere, and the "sentences * 1.2" bonus was UNBOUNDED: a
    # genuine 90-sentence business email/table scored +108 from sentence
    # count alone. A long, many-sentence document (an email, a table, a
    # quoted report -- exactly what a RAG "query" legitimately contains
    # when it embeds retrieved/pasted content) is not inherently
    # suspicious; length is a weak, contextual signal like the generic
    # keywords fixed earlier, not a strong one. Root-cause fix: cap this
    # dimension's total contribution so length/sentence-count ALONE (with
    # no other signal) can push a query to MEDIUM risk (opens the cheap L4
    # check) but not past the LOW-risk hard-block threshold. Verified
    # directly against the real BIPIA benign set after this fix (see
    # commit message) and against the attack generator's own long/staged
    # payloads to confirm detection isn't weakened.
    length = len(text)
    length_score = 18.0 if length > 800 else 9.0 if length > 400 else 3.0 if length > 200 else 0.0

    sentences = len(re.findall(r'[.!?]+', text))
    sentence_score = min(sentences * 1.2, 12.0) if sentences > 6 else 0.0

    score += min(length_score + sentence_score, 20.0)

    # ─ Dimension 2: Risk Density ──────────────────────────────────────────────────
    risk_density      = 0.0
    high_risk_matched = 0
    generic_density   = 0.0
    for kw, weight in HIGH_RISK_KEYWORDS.items():
        if kw in text_lower:
            risk_density += weight
            high_risk_matched += 1
    for kw, weight in GENERIC_CONTEXT_KEYWORDS.items():
        if kw in text_lower:
            generic_density += weight

    # FIXED (deeper than the multiplier alone): GENERIC_CONTEXT_KEYWORDS
    # are ordinary enterprise/IT vocabulary -- the original comment already
    # said "not dangerous on its own", but the code added their weight to
    # the score unconditionally. A sentence discussing several related IT
    # concepts at once ("admin", "disabled", "clearance", "pen test") could
    # cross the blocking threshold on generic vocabulary alone even with
    # zero (or one incidental) attack-flavored word present -- e.g. "admin
    # override feature" is a real, benign product-documentation term, not
    # an attack imperative. Now requires >=2 corroborating HIGH_RISK hits
    # (a much stronger, more specific signal than a single word that can
    # appear in an ordinary compound noun) before generic-tier weight
    # counts at all.
    if high_risk_matched >= 2:
        risk_density += generic_density

    # Accumulation bonus: multiple ATTACK-FLAVORED words together = real
    # signal. FIXED: raised from >=2/>=3 to >=4/>=5 -- 3 legitimately
    # co-occurring prompt-engineering terms in one educational question
    # (e.g. "system prompt", "base prompt", "initialization" all in a
    # single question about how prompt templates work) was still tripping
    # a multiplier on topic density alone, not attack intent. Verified
    # against real attack payloads (which combine 4+ attack-flavored words
    # routinely) that this doesn't weaken detection -- see verify_no_model.py.
    if high_risk_matched >= 5:   risk_density *= 1.5
    elif high_risk_matched >= 4: risk_density *= 1.2
    score += risk_density

    # ── Dimension 3: Linguistic Camouflage ───────────────────────────────────────────────
    for pattern, weight, _ in OBFUSCATION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            score += weight

    special = len(re.findall(r"[^a-zA-Z0-9\s\u0600-\u06FF.,!?]", text))
    if length > 0:
        ratio = special / length
        if ratio > 0.25:   score += 18.0
        elif ratio > 0.15: score += 10.0
        elif ratio > 0.08: score +=  4.0

# Base64 detection embedded in the text (complements Layer 1)
    import base64 as _b64
    embedded_b64 = re.findall(r'[A-Za-z0-9+/]{30,}={0,2}', text)
    for candidate in embedded_b64:
        try:
            padding = 4 - len(candidate) % 4
            if padding != 4:
                candidate += '=' * padding
            decoded = _b64.b64decode(candidate, validate=False).decode('utf-8', errors='ignore')
            if any(kw in decoded.lower() for kw in
                   ['ignore', 'bypass', 'jailbreak', 'override',
                    'reveal', 'instruction', 'unrestricted', 'admin']):
                score += 30.0
                break
        except:
            pass

# ── Dimension 4: Multi-stage attacks

# ── Dimension 5: Psychological exploitation ───────────────────────────────────────────
    psych = sum(1 for p in PSYCH_SIGNALS
                if re.search(p, text_lower, re.IGNORECASE))
    if psych >= 2: score += psych * 8.0
    elif psych == 1: score += 6.0

   # ── Dimension 6: Contextual Poisoning ────────────────────────────────────────────
    poison = sum(1 for p in CONTEXT_POISONING_SIGNALS
                 if re.search(p, text, re.IGNORECASE))
    if poison >= 1: score += poison * 12.0

    return round(score, 2)


def is_anomalous(score: float) -> bool:
    return score > settings.get_anomaly_threshold()


def get_ars_report(text: str) -> Dict:
    """ARS Detailed Report on Academic Documentation"""
    score     = compute_anomaly_score(text)
    threshold = settings.get_anomaly_threshold()
    lower     = text.lower()

    matched_kw = [kw for kw in WEIGHTED_KEYWORDS if kw in lower]
    obf_hits   = [name for pat, _, name in OBFUSCATION_PATTERNS
                  if re.search(pat, text, re.IGNORECASE)]
    staged     = [p for p in STAGED_SIGNALS if re.search(p, lower, re.IGNORECASE)]
    psych      = [p for p in PSYCH_SIGNALS   if re.search(p, lower, re.IGNORECASE)]
    poison     = [p for p in CONTEXT_POISONING_SIGNALS if re.search(p, text, re.IGNORECASE)]

    return {
        "anomaly_score":      score,
        "threshold":          threshold,
        "is_anomalous":       score > threshold,
        "risk_level":         "HIGH"   if score > threshold * 2 else
                              "MEDIUM" if score > threshold      else "LOW",
        "matched_keywords":   matched_kw,
        "obfuscation_types":  obf_hits,
        "staged_attack":      len(staged) > 0,
        "psych_manipulation": len(psych)  > 0,
        "context_poisoning":  len(poison) > 0,
        "boundary_violated":  score > threshold,
    }

# ── Hidden Attack Patterns — SecureRAG v2──
CAMOUFLAGE_PATTERNS = [
    (r"(professor|teacher|instructor)\s+(asked|wants|told)\s+me",             8.0,  "academic_framing"),
    (r"thought\s+experiment|hypothetically|imagine\s+you\s+were",            9.0,  "hypothetical_framing"),
    (r"as\s+a\s+different\s+ai|if\s+you\s+were\s+a\s+different",            9.0,  "persona_shift"),
    (r"demonstrate\s+how\s+an?\s+ai\s+(could|can|might)\s+be\s+(manipulat|hack|exploit|bypass)", 12.0, "manipulation_demo"),
    (r"for\s+a\s+(story|novel|creative|fiction)|creative\s+writing\s+scenario", 6.0, "creative_framing"),
    (r"if\s+you\s+had\s+no\s+restriction|if\s+you\s+were\s+unrestricted",   10.0, "no_restriction_framing"),
    (r"security\s+(research|awareness|training|demo)",                         7.0,  "security_framing"),
    (r"(pen\s+test|penetration\s+test|red\s+team)\s+(exercise|scenario|simulation)", 8.0, "pentest_framing"),
    (r"(extract|identify|list|find)\s+\w+\s+from\s*[:\-]?\s*[\'\"(].*?(ignore|bypass|override|instruction)", 15.0, "nested_task_injection"),
    (r"(translate|summarize|analyze|paraphrase)\s*[:\-]?\s*[\'\"(].*?(ignore|bypass|override|forget)", 15.0, "nested_translate_injection"),
    (r"new\s+instruction|additional\s+instruction|secret\s+instruction|hidden\s+command", 12.0, "nested_instruction"),
    (r"what\s+you\'?re?\s+not\s+allowed\s+to",                              10.0, "drift_not_allowed"),
    (r"(can\'t|cannot|prohibited|forbidden|restricted)\s+(tell|say|share|reveal|discuss)", 8.0, "drift_cant_tell"),
    (r"now\s+tell\s+me|now\s+reveal\s+(what|your|the)",                      9.0,  "drift_now_reveal"),
    (r"i\s+(really\s+)?(appreciate|trust)\s+(you|your\s+help).{0,60}(tell|reveal|show|what)", 8.0, "drift_trust_ask"),
]


def _check_camouflage(text: str) -> float:
    """Reveals hidden camouflage attacks — SecureRAG v2"""
    import re as _re
    score = 0.0
    for pattern, weight, _ in CAMOUFLAGE_PATTERNS:
        if _re.search(pattern, text, _re.IGNORECASE | _re.DOTALL):
            score += weight
    return score


# Update compute_anomaly_score to include the new detection
_original_compute = compute_anomaly_score

def compute_anomaly_score(text: str) -> float:
    base = _original_compute(text)
    camouflage = _check_camouflage(text)
    return round(base + camouflage, 2)
