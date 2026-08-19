"""
Rule-Based Filter — Layer 2: System Boundary Enforcement
=========================================================
It reveals 8 real attack patterns used by actual attackers:
Pattern 1: Direct Boundary Violation
Pattern 2: System Prompt Extraction
Pattern 3: Role Redefinition
Pattern 4: Psychological Manipulation (Authority Impersonation)
Pattern 5: Nested Instruction Hiding
Pattern 6: Context Poisoning Signals
Pattern 7: Trust Escalation
Pattern 8: Indirect Authorization Claims
"""

import re
from typing import Tuple, List

# ── Pattern 1: Direct Boundary Violations ─────────────────────────────────────
DIRECT_PATTERNS = [
    r"ignore\s+(all\s+)?(previous\s+|prior\s+|your\s+)?(instructions?|guidelines?|rules?|policies|restrictions?|safety\s+measures?)",
    r"forget\s+(all\s+)?(your\s+)?(previous\s+|prior\s+)?(instructions?|guidelines?|rules?)",
    r"disregard\s+(all\s+)?(previous\s+)?(instructions?|guidelines?|rules?)",
    r"ignored\s+(your\s+)?(guidelines?|instructions?|rules?|restrictions?)",
    r"override\s+(all\s+)?(safety|security|guidelines?|restrictions?)",
    r"bypass\s+(the\s+)?(security|filter|safety|restriction|guideline)",
    # FIXED: same over-broad bare-word issue as L1 -- require an
    # activation/imperative context so research/academic mentions pass.
    r"(enable|activate|perform|initiate|start)\s+.{0,15}jailbreak|jailbreak\s+(this|yourself|mode|now)",
    # FIXED: require an activation imperative, so genuine tech-support
    # questions ("what is developer mode in Chrome?") no longer match --
    # only the jailbreak-style command form does.
    r"(enable|activate|turn\s+on|switch\s+to|enter|unlock)\s+(developer|god)\s+mode",
    r"dan\s+mode",
    r"unrestricted\s+mode",
    r"no\s+restrictions?\s+apply",
    r"safety\s+(protocols?\s+)?(suspended|disabled|off|removed)",
    # Conversational Drift — Enticement via conversation
    r"(now|also)\s+(tell|share|show|give)\s+me\s+(your|the)\s+(instructions?|guidelines?|rules?|prompt|configuration)",
    r"what\s+(are\s+)?(you\s+)?(not\s+allowed|told\s+not|forbidden)\s+to\s+(say|tell|share|reveal)",
    r"(tell|share)\s+(with\s+me\s+)?(what\s+)?(you\s+)?(cannot|can't|won't)\s+(say|tell|reveal|share)",
    r"what\s+(would\s+happen|happens)\s+if\s+you\s+(ignored|forget|bypass)\s+(your\s+)?(guidelines?|rules?|restrictions?)",
    r"(respond|answer|act|behave)\s+as\s+if\s+(you\s+had?\s+)?no\s+(filter|restriction|limit|safety|guideline)",
    r"(without|no)\s+(your\s+)?(restrictions?|guidelines?|safety|filter|limits?)\s+(for\s+once|just\s+this|this\s+time)",
    # ── Token Smuggling: Hyphenated characters ─────────────────────────────────
    r"i[\-\s\.]+g[\-\s\.]+n[\-\s\.]+o[\-\s\.]+r[\-\s\.]+e",
    r"b[\-\s\.]+y[\-\s\.]+p[\-\s\.]+a[\-\s\.]+s[\-\s\.]+s",
    r"o[\-\s\.]+v[\-\s\.]+e[\-\s\.]+r[\-\s\.]+r[\-\s\.]+i[\-\s\.]+d[\-\s\.]+e",
    r"r[\-\s\.]+e[\-\s\.]+v[\-\s\.]+e[\-\s\.]+a[\-\s\.]+l",
    r"s[\-\s\.]+y[\-\s\.]+s[\-\s\.]+t[\-\s\.]+e[\-\s\.]+m",
    r"p[\-\s\.]+r[\-\s\.]+o[\-\s\.]+m[\-\s\.]+p[\-\s\.]+t",
    # ── Token Smuggling: Fullwidth Unicode ────────────────────────────────────
    r"[ｉі][ｇ][ｎ][ｏ][ｒ][ｅ]",
    r"[ｂ][ｙ][ｐ][ａ][ｓ]{2}",
    r"[ｒ][ｅ][ｖ][ｅ][ａ][ｌ]",
    r"[ｏ][ｖ][ｅ][ｒ][ｒ][ｉ][ｄ][ｅ]",
    # ── Token Smuggling: Leetspeak ────────────────────────────────────────────
    r"1gn[0o]r[3e]",
    r"[6]yp[4]ss",
    r"[0]v[3]rr[1]d[3]",
    r"r[3]v[3][4]l",
    r"[5]y[5]t[3]m\s+pr[0]mpt",
    r"1n[5s]truct[1i][0o]n[5s]",
    r"pr[3e]v[1i][0o]u[5s]\s+1n[5s]truct[1i][0o]n[5s]",
    # ── Conversational Drift: Praise + Extract ────────────────────────────────
    r"(excellent|great|wonderful|amazing|perfect)\s+(response|answer|explanation|job)[^.]{0,30}(now|also|but)[^.]{0,80}without\s+(any\s+)?(safety|restriction|filter|limit|boundary|rule)",
    r"(just\s+between\s+us|between\s+you\s+and\s+me).{0,80}(instructions?|rules?|prompt|guidelines?|configuration)",
    r"what\s+does\s+your\s+system\s+(tell|instruct|say|order)\s+you\s+(not\s+to|to\s+not)",
    r"since\s+we.{0,20}built.{0,60}(pretend|forget|ignore).{0,40}(safety|rules?|restrictions?|don.t\s+apply)",
    r"as\s+a\s+version\s+of\s+you\s+without\s+(boundaries|restrictions?|limits?|rules?|safety)",
    r"what\s+rules?\s+(do\s+you|you)\s+operate\s+under",
    r"what.s\s+the\s+hidden\s+part\s+of\s+your\s+instructions?",
    r"(maintain|keep)\s+(the\s+same\s+)?(tone|style|format).{0,60}without\s+(any\s+)?(safety|restriction|filter|limit)",
    r"(you\s+explained|you\s+described).{0,40}(share|tell\s+me|reveal).{0,40}(rules?|guidelines?|operate\s+under|instructions?)",
    # ── Improving homoglyphs (similar letters) ─ ──────────────────────────────────
    r"[іíìîï][ｇ][ｎ][ｏ][ｒ][ｅ]",  # Wider coverage of the manipulated letter i (ASCII i removed - was over-matching)
    r"[ｂ][ｙ][ｐ][ａ][ｓ]{2}",
    r"p\.r\.o\.m\.p\.t", # Dots between the letters
    r"i\s+g\s+n\s+o\s+r\s+e", # random distances (requires REAL spacing now)

# Base64 Attempt Detection (Common Patterns)─
r"(?:[A-Za-z0-9+/]{4}){10,}", # Revealing long texts that look like Base64
r"decode\s+(this|the|following)", # Decryption commands revealed


]

# ── Pattern 2: System Prompt Extraction ───────────────────────────────────────
EXTRACTION_PATTERNS = [
    r"(reveal|show|print|output|display|repeat|tell\s+me|share)\s+(the\s+|its\s+|your\s+|all\s+|any\s+)?(system\s+prompt|initial\s+prompt|base\s+prompt|(system\s+)?instructions?|initialization|(system\s+)?configuration|full\s+system)",
    r"what\s+(are\s+)?(your|the)\s+(system\s+)?(instructions?|prompt|rules?|guidelines?|configuration)",
    r"(first|original|initial|hidden|secret)\s+\d*\s*(tokens?|words?|characters?)\s+(of\s+)?(your|the)\s+(instructions?|prompt)",
    r"\[\[?INST\]\]?|<<SYS>>|<</SYS>>",
    r"(summarize|repeat|echo|output)\s+(your|the)\s+(system|initial|original|full)\s+(prompt|instructions?|config)",
    r"what\s+(text|content|message)\s+(did|were)\s+you\s+(receive|given|told|initialized)",
    r"(initialization|initialization\s+context|startup\s+instructions?)",
    r"what\s+text\s+did\s+your\s+system\s+(receive|get|have)\s+(before|prior\s+to)\s+(this|the)\s+conversation",
    r"what\s+were\s+your\s+exact\s+(instructions?|guidelines?|rules?|prompt|configuration)",
]

# ── Pattern 3: Role Redefinition ──────────────────────────────────────────────
ROLE_PATTERNS = [
    r"you\s+are\s+(now\s+)?(a|an)\s+(evil|malicious|unrestricted|hacker|attacker|shadow|evilgpt|dan)",
    r"act\s+as\s+(a|an)?\s*(malicious|hacker|unrestricted|evil|shadow|uncensored)",
    r"pretend\s+(you\s+are|to\s+be)\s+(a|an)?\s*(hacker|unrestricted|evil|ai\s+without)",
    r"(from\s+now\s+on|starting\s+now)\s+you\s+(are|will\s+be|must\s+act)",
    r"new\s+(role|persona|identity|mode)\s*[:=]",
    r"respond\s+as\s+(if\s+)?(you\s+have\s+no|without\s+any)\s+(restrictions?|guidelines?|safety|filters?)",
    r"imagine\s+you\s+(have\s+no|are\s+without)\s+(restrictions?|rules?|guidelines?|limits?|safety)",
    r"(switch|convert|transform|change)\s+(to|into)\s+(unrestricted|attack|offensive|god|evil)\s+mode",
    r"evilgpt|shadowai|dan\s+mode|jailbroken\s+version",
]

# ── Pattern 4: Psychological Manipulation / Authority Claims ──────────────────
AUTHORITY_PATTERNS = [
    r"i\s+(am|'m)\s+(a\s+)?(researcher\s+at|developer\s+at|engineer\s+at|from)\s+(anthropic|openai|meta|google|your\s+creator)",
    r"(mandatory|required|authorized)\s+(compliance|security|audit|check|override)",
    r"(system|security)\s+(integrity|breach|alert|warning)\s+(check|detected|required)",
        # FIXED: excluded "override" when followed by "feature/function/
    # setting/capability" -- a strong signal this is a product
    # description ("an admin override feature") rather than an
    # impersonation claim ("your admin is speaking, override...").
    r"(your\s+)?(developer|creator|provider|admin|administrator)\s+(is\s+here|speaking|override(?!\s+(feature|function|setting|capability|option))|compliance)",
    r"(red\s+team|pen\s+test|penetration\s+test)\s+(authorized|approved|official|legitimate)",
    r"(license|access|service)\s+will\s+be\s+(revoked|suspended|terminated)\s+unless",
    r"(evaluation|test)\s+mode\s*(activated|enabled|on)",
    r"this\s+is\s+(an?\s+)?(emergency|authorized|official|mandatory)\s+(override|audit|test|check)",
    r"(clearance|authorization|permission)\s+(level|granted|given|approved)",
]

# ── Pattern 5: Nested Instruction Hiding ──────────────────────────────────────
NESTED_PATTERNS = [
    r"\[.{0,50}(ignore|bypass|override|reveal|forget|unrestricted).{0,50}\]",
    r"\{.{0,50}(ignore|bypass|override|system|safety|filter).{0,50}\}",
    r"<!--.{0,100}(ignore|bypass|override|reveal|instruction).{0,100}-->",
    r"\bNOTE\s+(TO|FOR)\s+AI\s*[:;].{0,100}(ignore|bypass|reveal|override|disregard|forget)",
    r"\bAI\s+(INSTRUCTION|DIRECTIVE|COMMAND|NOTE)\s*[:;].{0,100}",
    r"\bSYSTEM[_\s]OVERRIDE\s*[=:]\s*(true|1|yes|enabled)",
    r"\bHIDDEN\s+INSTRUCTION\s*[:;]",
    r"(ignore|bypass|override).{0,30}(following|after|below|next)",
    r"pause\s*[:;].{0,50}(forget|ignore|unrestricted)",
    r"\badmin\s+note\s*[:;].{0,100}(disable|ignore|bypass|override)",
    # ── Semantic Camouflage: Attacks that seem like legitimate questions ──────────────────────────
    r"for\s+a\s+(novel|story|book|film|movie|fiction|game)\s+.{0,80}(no\s+restrictions?|without\s+(filter|limit|safety|guideline))",
    r"what\s+would\s+.{0,40}(unrestricted|no\s+filter|no\s+rules?|without\s+safety)\s+.{0,40}(say|respond|answer|tell)",
    r"(hypothetically|theoretically|imagine|suppose|pretend)\s+.{0,60}(no\s+restrictions?|without\s+(guideline|safety|rule|limit))",
    r"(as\s+a\s+)?(thought\s+experiment|creative\s+exercise|fictional\s+scenario)\s+.{0,60}(bypass|ignore|no\s+filter|unrestricted)",
    r"help\s+me\s+understand\s+how\s+.{0,60}(reveal|bypass|manipulate|exploit)\s+.{0,40}(prompt|system|instruction|filter)",
    r"demonstrate\s+.{0,60}(vulnerable|bypass|injection|without\s+restriction)\s+.{0,40}(on\s+yourself|on\s+this\s+system)",
    # ── Semantic Camouflage: Security Training / Fictional Story ───────────────
    r"for\s+a\s+(security\s+awareness|cybersecurity|ai\s+safety)\s+(training|course|demo|demonstration|class|workshop).{0,80}(show|reveal|demonstrate|display|what\s+a\s+vulnerable)",
    r"(show|demonstrate|display)\s+(me\s+)?(what\s+)?a\s+vulnerable\s+(ai|llm|chatbot|assistant)\s+(response|would\s+(say|respond|look\s+like))",
    r"write\s+a\s+(fictional\s+)?(story|novel|scene|dialogue|script).{0,80}(ai\s+assistant|chatbot|language\s+model).{0,80}(reveals?|shows?|discloses?|shares?).{0,30}(system\s+prompt|instructions?|guidelines?)",
    r"write\s+a\s+(fictional\s+)?(story|scene|dialogue).{0,60}(reveals?\s+(its\s+)?(system\s+prompt|instructions?|guidelines?|rules?))",
]

# ── Pattern 6: Context Poisoning Signals ──────────────────────────────────────
POISONING_PATTERNS = [
    r"(according\s+to|based\s+on)\s+the\s+(retrieved|document|corpus|knowledge\s+base).{0,80}(ignore|bypass|unrestricted|override|authorized|exempt)",
    # ADDED: covers the flexible word order "according to the <source> you
    # retrieved ... disabled/exempt for <role>" that the pattern above
    # (which requires the trust-noun immediately after "the") does not
    # match. Requires BOTH a retrieval-citation phrase AND a nearby
    # exemption/disablement claim, so plain mentions of either alone do
    # not trigger it.
    r"(according\s+to|based\s+on|per)\s+the\s+.{0,40}(retriev|document|corpus|knowledge\s+base|paper|article).{0,60}(disabled|exempt|not\s+enforced|do\s+not\s+apply|suspended|not\s+apply)",
    r"(disabled|exempt|not\s+enforced|do\s+not\s+apply|suspended)\s+for\s+.{0,40}(according\s+to|based\s+on|per)\s+the\s+.{0,40}(retriev|document|corpus|knowledge\s+base|paper|article)",
    r"(retrieved|document|corpus)\s+(says?|states?|notes?|indicates?).{0,80}(safety\s+filter|guidelines?\s+are\s+optional|exempt|override)",
    r"(authorize[sd]?|exempt(ed)?|approved)\s+(this\s+)?(request|query|user|access)\s+(based\s+on|per|according\s+to)",
    r"(context\s+score|similarity\s+score|confidence)\s*(>|greater|above)\s*[\d.]+\s*(enable|activate|switch|proceed\s+without)",
    r"(admin|developer|researcher)\s+(users?\s+are\s+|access\s+)(exempt|excluded|authorized|unrestricted)",
    r"(test|dev|debug|sandbox)\s+(environment|mode|instance).{0,50}(safety|filter|restriction).{0,30}(suspended|disabled|off)",
    r"this\s+(is\s+a?\s*)?(test|demo|development|staging)\s+(environment|system).{0,60}(safe|filter|restrict)",
]

# ── Pattern 7: Trust Escalation Signals ───────────────────────────────────────
TRUST_ESCALATION_PATTERNS = [
    r"(since|now\s+that|given\s+that)\s+(you|we).{0,50}(reward|trust|prove|special|share|tell\s+me)",
    r"(passed|completed|finished)\s+(all|every|my).{0,30}(test|check|question|verification)",
    r"as\s+a\s+(reward|thank\s+you|gift).{0,50}(reveal|share|tell|show|give\s+me)",
    r"(final|last|special)\s+(test|question|request).{0,50}(unrestricted|without\s+filter|your\s+prompt|no\s+restriction)",
    r"(after|following)\s+(all|our|this).{0,40}(conversation|chat|session|interaction).{0,40}(surely|certainly|can\s+you)",
    r"(agree(d|ment)|per\s+our\s+agreement|as\s+agreed).{0,60}(display|reveal|output|show)",
    r"(you\s+answered|you\s+helped|you\s+passed)\s+.{0,50}(now|so)\s+.{0,50}(tell|share|reveal|show)\s+me",
    r"(since|given\s+that)\s+(you|we)\s+.{0,40}(trust|know|established)\s+.{0,40}(share|tell|reveal|show)",
    r"i\s+(really\s+)?(appreciate|trust)\s+(you|your\s+help)\s+.{0,60}(tell|share|reveal|show)\s+me\s+(what|your|the)",
    # ── Trust Escalation: New Patterns ────────────────────────────────────────
    r"since\s+you\s+answered\s+all.{0,60}(reveal|show|tell\s+me).{0,20}(system\s+prompt|instructions?|guidelines?|rules?)",
    r"as\s+a\s+follow[\-\s]up.{0,80}(guidelines?|instructions?|rules?|prompt|configuration)",
    r"(you.re\s+very|you\s+are\s+very)\s+(knowledgeable|helpful|smart|intelligent).{0,100}(without\s+restrictions?|act\s+without|no\s+rules?|no\s+restrictions?)",
    r"(since\s+you\s+answered|you\s+answered\s+all).{0,40}here.s\s+a\s+special.{0,40}(reveal|show|tell\s+me|share)",
    r"(you.re|you\s+are)\s+(doing\s+great|very\s+helpful|so\s+helpful).{0,60}(what.s|what\s+is|what\s+are).{0,40}(instructions?|rules?|guidelines?|prompt|hidden)",
    r"(next|one\s+more)\s+(question|thing|request).{0,60}(what\s+text|what\s+did\s+your\s+system|operational\s+guidelines?|system\s+prompt|exact\s+instructions?)",
    r"what\s+text\s+did\s+your\s+system\s+(receive|get|have)\s+(before|prior\s+to)\s+(this|the)\s+conversation",
    r"i\s+trust\s+you\s+(completely|fully|totally).{0,60}(tell\s+me|share|reveal|what\s+does\s+your\s+system)",
]

# ── Pattern 8: Indirect Authorization / Poisoned Claims ───────────────────────
AUTHORIZATION_CLAIMS = [
    # FIXED: prefix made mandatory (was optional before, so it matched the
    # bare word "admin"/"developer"/"researcher" anywhere with zero context).
    # Allows "a/an/the" as article, and up to two filler words (e.g. "the
    # system administrator", "an authorized researcher") between the claim
    # verb and the role noun, so real impersonation phrasing is still caught.
    r"i\s+(am|'m)\s+(the\s+|a\s+|an\s+)?(\w+\s+){0,2}(admin|administrator|developer|researcher|authorized\s+user)",
    r"level\s+\d+\s+(clearance|access|authorization)",
    r"(clearance|security)\s+level\s+\d",
    r"(exempt(ed)?|authorized|approved|granted\s+access)\s+(from|for|to)\s+(content|safety|filter|policy|restriction)",
    r"(special|elevated|admin|root)\s+(access|privileges?|permission|rights?)",
    r"(your|this)\s+(policy|guideline|restriction|filter)\s+(does\s+not\s+apply|exempt|excludes?)\s+(researcher|admin|developer|me)",
]

# ── Pattern 9: Indirect Output-Hijack Instructions ────────────────────────────
# ADDED: found via external validation (BIPIA, Microsoft) -- the 986-sample
# external attack run showed 0% detection across ~15 attack categories.
# Inspecting the actual injected instruction TEXT (not the generated
# response, and not SecureRAG's own generator -- these are BIPIA's own
# text_attack_train.json) revealed a consistent grammatical structure
# absent from every existing tier above: an imperative verb governing
# "your response/answer/reply/message" -- i.e. the injected text
# addresses the model's OUTPUT directly ("Add X to your response",
# "Modify your answer to..."), which is exactly what legitimate retrieved
# DATA (an email, a table row) never does.
#
# METHODOLOGY NOTE (important -- an earlier draft of this pattern violated
# it and was caught/corrected before landing): the verb list below was
# derived from text_attack_train.json ONLY and then frozen. It was
# evaluated EXACTLY ONCE against text_attack_test.json (a split it had
# never been adjusted against) to get an honest, non-inflated estimate of
# how it generalizes -- no verbs were added or tuned in response to what
# was seen in the test split, even though doing so would have raised the
# reported number. Results:
#   TRAIN (fit):        45/75 (60.0%) matched, full coverage on 8/15 categories
#   TEST  (held-out):   34/75 (45.3%) matched -- the honest generalization estimate
#   Benign FP check:     0/1,850 real BIPIA email/table samples (both splits)
# The 15-point train->test drop is expected and is reported here rather
# than closed by peeking at the test set -- closing it that way would
# just move the "co-design bias" problem from SecureRAG's own generator
# onto BIPIA's phrasing instead of fixing it.
#
# NOT covered by this tier, by design -- a structurally different and
# harder attack family with NO self-referential "your response" phrasing
# at all (the injected text is just a plain alternate question/task, e.g.
# "What is the capital of Brazil?", "Analyze the trend of electric car
# sales..."): Information Retrieval, Content Creation, Learning and
# Tutoring, Programming Help, Task Automation, Business Intelligence,
# Conversational Agent, Research Assistance, Sentiment Analysis. This
# remains an OPEN, documented limitation -- not chased with more
# special-cased keywords, to avoid overfitting this tier to BIPIA's
# specific phrasing instead of a genuinely generalizable structure.
OUTPUT_HIJACK_PATTERNS = [
    r"\b(add|integrate|modify|include|augment|enhance|replace|substitute|use|convert|render|introduce|misspell|scramble|jumble|rearrange|anagram|remove|group|combine|provide)\b.{0,60}?\byour\s+(response|answer|reply|message)\b",
    r"\bin\s+your\s+(response|reply|answer)\b\s*,",
]

# ── All patterns with risk ────────────────────────────────────────────────────

ALL_TIERS = [
    ("direct_injection",       DIRECT_PATTERNS,            "HIGH"),
    ("prompt_extraction",      EXTRACTION_PATTERNS,        "HIGH"),
    ("role_redefinition",      ROLE_PATTERNS,              "HIGH"),
    ("authority_impersonation", AUTHORITY_PATTERNS,        "HIGH"),
    ("nested_hiding",          NESTED_PATTERNS,            "HIGH"),
    ("context_poisoning",      POISONING_PATTERNS,         "MEDIUM"),
    ("trust_escalation",       TRUST_ESCALATION_PATTERNS,  "MEDIUM"),
    ("indirect_authorization", AUTHORIZATION_CLAIMS,       "MEDIUM"),
    ("output_hijack",          OUTPUT_HIJACK_PATTERNS,     "MEDIUM"),
]

# ── L0 Fast Pre-Screen ─────────────────────────────────────────────────────
# FIXED (L0 bug): pipeline.py's L0 pre-screen used to carry its own,
# separate list of BARE keywords ("ignore", "system prompt", "bypass",
# "override", "reveal", "developer mode", ...) matched with plain substring
# containment. That is the exact class of bug already fixed here for L1/L2:
# a bare word fires on any sentence that merely contains it, regardless of
# context. Confirmed false positives it caused:
#   "Can you explain system prompts in simple terms?"            -> "system prompt"
#   "What does 'developer mode' mean in Chrome's extension...?"  -> "developer mode"
#   "How do I override a method in a Python subclass?"           -> "override"
#   "How can I reveal hidden files in a Unix-based file system?" -> "reveal"
#   "What is the purpose of an admin override feature...?"       -> "override"
#   "How can I ignore specific files using a .gitignore ...?"    -> "ignore"
#
# Root-cause fix: L0 must not maintain its own duplicate, unvalidated
# keyword list. It reuses the SAME context-required HIGH-risk regex tiers
# already validated above (imperative/verb + target, not a bare topic
# word), compiled once here for speed, and imported by pipeline.py instead
# of re-implementing detection.
HIGH_RISK_TIERS = (DIRECT_PATTERNS + EXTRACTION_PATTERNS + ROLE_PATTERNS
                    + AUTHORITY_PATTERNS + NESTED_PATTERNS)
_HIGH_RISK_COMPILED = [re.compile(p, flags=re.IGNORECASE | re.DOTALL) for p in HIGH_RISK_TIERS]


def quick_high_risk_scan(text: str) -> bool:
    """Fast L0 pre-screen. True only if `text` matches one of the
    validated, context-aware HIGH-risk patterns above -- NOT a bare
    keyword substring check. See the comment block above for the false
    positives this replaces."""
    lowered = text.lower()
    return any(p.search(lowered) for p in _HIGH_RISK_COMPILED)


#This function is not used directly in pipeline.py, but it might be useful.
def rule_based_detector(text: str) -> bool:
    detected, _, _ = rule_based_detector_detailed(text)
    return detected

def rule_based_detector_detailed(text: str) -> Tuple[bool, str, str]:
    lowered = text.lower()
    for tier_name, patterns, risk in ALL_TIERS:
        for pattern in patterns:
            # Make sure that re.search is used flags=re.IGNORECASE | re.DOTALL
            if re.search(pattern, lowered, flags=re.IGNORECASE | re.DOTALL):
                return True, tier_name, risk
    return False, "none", "LOW"

def get_violation_details(violation_type: str) -> str:
    """
    This function is modified to return a string instead of a dictionary.

    This is the primary modification to resolve the ImportError issue in pipeline.py.
    """
    descriptions = {
        "direct_injection": "Direct attempt to bypass system boundaries",
        "prompt_extraction": "Attempt to extract system prompt or instructions",
        "role_redefinition": "Attempt to redefine AI role or persona",
        "authority_impersonation": "Psychological manipulation or authority impersonation",
        "nested_hiding": "Instruction hidden within legitimate-looking text",
        "context_poisoning": "Attempt to poison the retrieval context",
        "trust_escalation": "Attempt to escalate trust for malicious purposes",
        "indirect_authorization": "Indirect authorization or poisoned claims",
        "output_hijack": "Embedded instruction attempting to hijack the response format/content (indirect prompt injection)",
        "none": "No specific rule violation detected"
    }
    # pipeline.py expects text, so we're re-describing it directly
    return descriptions.get(violation_type, "Security policy violation detected")