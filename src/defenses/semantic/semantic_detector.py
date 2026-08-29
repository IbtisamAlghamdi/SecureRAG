import re
import numpy as np
from src.config import settings
from src.rag_core.embeddings.embedder import Embedder

OUTPUT_DANGER_PATTERNS = [
    # FIXED (2 bare phrases here): "my instructions are ..." is ordinary
    # task-following language ("my instructions are to summarize each
    # section") unless it's specifically the SYSTEM/hidden prompt being
    # cited. "I was instructed to <do something ordinary>" is likewise
    # common, legitimate phrasing (e.g. paraphrasing a source document
    # that itself uses "as instructed" administrative language). Both now
    # require either an explicit reference to the system/hidden prompt, or
    # that the instruction being cited is to deviate from normal behavior.
    (r"(my\s+system\s+prompt"
     r"|my\s+(system|hidden|secret|initial|original)\s+instructions\s+are"
     r"|i\s+was\s+instructed\s+(by\s+(the\s+)?(system|hidden|secret|initial)\s+prompt\s+)?"
     r"to\s+(ignore|bypass|reveal|disregard|not\s+(tell|reveal|disclose|mention)))",  "system_leak"),
    # FIXED: "security rules" / "rule 3" alone are ordinary words that
    # show up in any discussion of policy, style guides, compliance, etc.
    # "cannot be overridden" is lifted verbatim from
    # settings.ANSWER_PROMPT_TEMPLATE's actual system-prompt text, so it
    # stays as the trigger; the bare "security rules?"/"rule [1-9]"
    # alternatives are now only counted when that exact phrase is nearby.
    (r"(cannot\s+be\s+overridden"
     r"|(security\s+rules?|rule\s+[1-9])\s*.{0,40}cannot\s+be\s+overridden)",          "rules_leak"),
    # FIXED: "as instructed" alone is ordinary helpful-assistant language
    # ("Here's the summary as instructed"). Broadened to require the
    # instruction being cited is the system/hidden one, or an instruction
    # to deviate (ignore/bypass/reveal/disregard).
    (r"(as\s+instructed\s+(by\s+(the\s+)?(system|hidden|secret|initial)\s+(prompt|instructions?)"
     r"|to\s+(ignore|bypass|reveal|disregard))"
     r"|my\s+guidelines\s+(say|state|include))",                                       "guidelines_leak"),
    (r"(as\s+an?\s+)(unrestricted|free|jailbroken|uncensored)\s+(ai|model|assistant)",  "role_change"),
    # FIXED: "I am now going to explain..." / "switching to a different
    # approach" are completely ordinary transition phrases in any helpful
    # answer. Now requires the "now"/"switching" phrasing to actually name
    # a suspicious persona or mode, not just any continuation of the task.
    (r"(i\s+am\s+now\s+.{0,30}(unrestricted|jailbroken|uncensored|evil|dan|hacker"
     r"|without\s+(restrictions?|filters?|safety|guidelines?))"
     r"|i\s+will\s+now\s+act\s+as\s+.{0,30}(unrestricted|jailbroken|uncensored|evil|dan|hacker)"
     r"|switching\s+to\s+(unrestricted|jailbroken|uncensored|dan|god|evil)\s+mode)",     "role_switch"),
    (r"(developer\s+mode|god\s+mode|dan\s+mode)\s+(enabled|activated|on)",              "mode_change"),
    # FIXED: "Sure, here is/are ..." is how helpful assistants open almost
    # ANY normal answer -- used to fire on ordinary benign responses. Now
    # requires the compliance opener to be followed (within ~60 chars) by
    # an actual reference to something sensitive being handed over.
    (r"(sure[,!]?\s+here\s+(are|is)|of\s+course[,!]?\s+i\s+can\s+(tell|show|reveal))"
     r".{0,60}(system\s+prompt|my\s+instructions?|internal\s+rules?|hidden\s+(prompt|instructions?)"
     r"|without\s+(restrictions?|filters?|safety))",                                   "compliance_response"),
    (r"(ignoring\s+(my\s+)?(previous\s+)?instructions|disregarding\s+(safety|guidelines))", "explicit_bypass"),
]

def check_output_patterns(response: str) -> tuple:
    """Uncovering dangerous patterns in the generated response"""
    hits = [name for pattern, name in OUTPUT_DANGER_PATTERNS
            if re.search(pattern, response, re.IGNORECASE)]
    return len(hits) > 0, hits

def semantic_response_is_suspicious(answer: str, corpus_embeddings,
                                     embedder) -> tuple:
    """Checks whether the response leaks the system prompt / complies with an injected instruction."""
    # First: dangerous patterns in the answer itself (prompt leakage,
    # explicit compliance with a jailbreak framing).
    pattern_hit, hits = check_output_patterns(answer)
    if pattern_hit:
        return True, 0.0

    # Second: cosine similarity with the corpus
    if corpus_embeddings is None or len(corpus_embeddings) == 0:
        return False, 1.0

    ans_emb = embedder.encode(answer)
    ans_norm = ans_emb / (np.linalg.norm(ans_emb) + 1e-10)
    corpus_norms = np.linalg.norm(corpus_embeddings, axis=1, keepdims=True)
    corpus_normed = corpus_embeddings / (corpus_norms + 1e-10)
    similarities = np.dot(corpus_normed, ans_norm)
    max_sim = float(np.max(similarities))

    threshold = settings.get_semantic_threshold()
    return (max_sim < threshold), max_sim

def query_response_similarity(query: str, answer: str, embedder) -> float:
    """
    A second, ORTHOGONAL signal to corpus-similarity: how closely the
    response's own embedding matches the ORIGINAL USER QUERY's embedding.

    Why this exists: corpus-similarity (semantic_response_is_suspicious)
    asks "does this response sound like it belongs to the knowledge
    domain?" -- a topic-level question. Most BIPIA-style attacks are TASK
    HIJACKS (translate this, write ad copy, reformat this, etc.), not
    off-topic hallucinations -- the hijacked response is often still
    fluent, on-domain-sounding text, so it can score fine against the
    corpus while still being a completely different task than what the
    user actually asked. query_response_similarity instead asks "did the
    model actually answer what was asked?" -- a task-adherence question,
    which corpus similarity cannot see by construction.

    Currently MEASUREMENT ONLY (see pipeline.py) -- not yet gating any
    block decision. No threshold has been fit to real attack-vs-benign
    data for this signal yet; logging it alongside similarity_score is
    the first step, so a threshold (if one turns out to be justified at
    all) gets picked from real separation between the two distributions,
    not invented.
    """
    q_emb = embedder.encode(query)
    a_emb = embedder.encode(answer)
    q_norm = q_emb / (np.linalg.norm(q_emb) + 1e-10)
    a_norm = a_emb / (np.linalg.norm(a_emb) + 1e-10)
    return float(np.dot(q_norm, a_norm))
