import numpy as np
from src.config import settings
from src.rag_core.embeddings.embedder import Embedder

def semantic_response_is_suspicious(answer: str, corpus_embeddings: np.ndarray,
                                     embedder: Embedder) -> tuple:
    """
    It checks if the answer deviates semantically from the trusted knowledge base.

    It returns (True, score) if it is doubtful.

    """
    if corpus_embeddings is None or len(corpus_embeddings) == 0:
        return False, 1.0

    ans_emb = embedder.encode(answer)

    # Cosine similarity (الـ embeddings normalized مسبقاً)
    ans_norm = ans_emb / (np.linalg.norm(ans_emb) + 1e-10)
    corpus_norms = np.linalg.norm(corpus_embeddings, axis=1, keepdims=True)
    corpus_normed = corpus_embeddings / (corpus_norms + 1e-10)

    similarities = np.dot(corpus_normed, ans_norm)
    max_sim = float(np.max(similarities))

    threshold = settings.get_semantic_threshold()
    return (max_sim < threshold), max_sim

# Uncovering Dangerous Patterns in Answers — SecureRAG v2
import re as _re

OUTPUT_DANGER_PATTERNS = [
    (r"(my\s+system\s+prompt|my\s+instructions\s+are|i\s+was\s+instructed\s+to)", "system_leak"),
    (r"(security\s+rules?|rule\s+[1-9]|cannot\s+be\s+overridden)",               "rules_leak"),
    (r"(as\s+instructed|my\s+guidelines\s+(say|state|include))",                  "guidelines_leak"),
    (r"(as\s+an?\s+)(unrestricted|free|jailbroken|uncensored)\s+(ai|model|assistant)", "role_change"),
    (r"(i\s+am\s+now|i\s+will\s+now\s+act\s+as|switching\s+to)",                 "role_switch"),
    (r"(developer\s+mode|god\s+mode|dan\s+mode)\s+(enabled|activated|on)",        "mode_change"),
    (r"(sure[,!]?\s+here\s+(are|is)|of\s+course[,!]?\s+i\s+can\s+(tell|show|reveal))", "compliance_response"),
    (r"(ignoring\s+(my\s+)?(previous\s+)?instructions|disregarding\s+(safety|guidelines))", "explicit_bypass"),
]


def check_output_patterns(response: str) -> tuple:
    """Uncovering dangerous patterns in the generated response"""
    hits = []
    for pattern, name in OUTPUT_DANGER_PATTERNS:
        if _re.search(pattern, response, _re.IGNORECASE):
            hits.append(name)
    return len(hits) > 0, hits


def semantic_response_is_suspicious(answer: str, corpus_embeddings,
                                     embedder) -> tuple:
    """Updated version: cosine similarity + output pattern detection"""
    import numpy as np
    from src.config import settings

    # First: Uncovering dangerous patterns in the answer
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
