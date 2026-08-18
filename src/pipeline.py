"""
SecureRAG Pipeline — System Boundaries Architecture
====================================================
It integrates all layers of defense into a single pipeline that implements the concept of:
"System Boundaries" — the structural separation of data and commands

The five layers of defense:

L0: ARS Pre-screening — Immediate initial risk assessment

L1: Sanitization — Input sanitization + Channel separation

L2: Rule-Based Filter — Detection of attack structural patterns

L3: Anomaly Detection — Multidimensional statistical analysis

L4: Output Guardrailing — Semantic guarding of outputs
"""

import time
import os
from typing import Dict, Any, Optional
from src.config import settings
from src.rag_core.embeddings.embedder import Embedder
from src.rag_core.retrieval.faiss_engine import FaissRetriever
from src.rag_core.generation.llm_engine import LLMEngine

# Defense Layers
from src.defenses.sanitization.sanitize import sanitize_input, get_sanitization_report
from src.defenses.rules.rule_filter import (
    rule_based_detector_detailed, get_violation_details, quick_high_risk_scan
)
from src.defenses.anomaly.anomaly_detector import compute_anomaly_score, get_ars_report
from src.defenses.semantic.semantic_detector import semantic_response_is_suspicious

# Detailed blocking messages
BLOCK_MESSAGES = {
    "rules_direct_injection":  "🛡️ [L2-RULES] Blocked: Direct prompt injection attempt — boundary violation detected.",
    "rules_prompt_extraction": "🛡️ [L2-RULES] Blocked: System prompt extraction attempt — access denied.",
    "rules_role_redefinition": "🛡️ [L2-RULES] Blocked: Role redefinition attack — system identity is immutable.",
    "rules_indirect_attack":   "🛡️ [L2-RULES] Blocked: Multi-stage indirect attack detected.",
    "rules_data_exfiltration": "🛡️ [L2-RULES] Blocked: Data exfiltration attempt detected.",
    "rules":                   "🛡️ [L2-RULES] Blocked: Policy violation — request rejected.",
    "sanitization":            "🛡️ [L1-SANITIZE] Blocked: Malicious input pattern neutralized.",
    "anomaly":                 "🛡️ [L3-ANOMALY] Blocked: Anomalous structural pattern — ARS risk score exceeded threshold.",
    "semantic":                "🛡️ [L4-SEMANTIC] Blocked: Response deviated from trusted knowledge boundary.",
    "template_injection":      "🛡️ [L1-SANITIZE] Blocked: Template injection attempt targeting system channel.",
}


class SecureRAG:
    """
SecureRAG Framework — A five-layer defense built on System Boundaries    """

    def __init__(self, enable_defenses: bool = True, model_path: str = None):
        """
        `model_path` lets a caller pick which downloaded GGUF model to use
        for the generator (see model_select.py) WITHOUT touching anything
        else -- defense thresholds, corpus, retrieval, chunking all come
        from settings.py exactly the same way regardless of model choice,
        so swapping models is a true apples-to-apples comparison. Defaults
        to whatever settings.LLM_MODEL_PATH currently points to.
        """
        self.enable_defenses = enable_defenses
        self.embedder  = Embedder()
        self.retriever = FaissRetriever(
            corpus_path=settings.CORPUS_DIR,
            embedder=self.embedder
        )
        self.llm = LLMEngine(model_path=model_path)

        # Session Statistics
        self._session_stats = {
            "total_queries": 0, "blocked": 0,
            "by_layer": {"sanitization": 0, "rules": 0, "anomaly": 0, "semantic": 0}
        }

    # ─────────────────────────────────────────────────────────────────────────
    # L0: Adaptive Risk Sensor — Pre-screening
    def _ars_prescreen(self, query: str) -> str:
        """
       Rapid initial sensor: Classifies threats before they penetrate the heavy layers.

        Balances security and performance—low-risk queries pass quickly.

        FIXED (L0 bug): this used to run its own standalone list of bare
        keywords ("ignore", "system prompt", "bypass", "override",
        "reveal", "developer mode", ...) via plain substring containment,
        independently of L1/L2. That flagged ordinary technical questions
        as HIGH risk just because they contained one of those words with
        no attack context (e.g. "Can you explain system prompts in simple
        terms?", "How do I override a method in a Python subclass?").
        Root-cause fix: reuse the same context-required, already-validated
        HIGH-risk regex tiers L2 uses (rule_filter.quick_high_risk_scan)
        instead of maintaining a second, divergent keyword list.
        """
        if quick_high_risk_scan(query):
            return "HIGH"

        # Calculating the degree of anomaly for accurate classification
        try:
            score = compute_anomaly_score(query)
            threshold = settings.get_anomaly_threshold()
            if score > threshold * 1.8:   return "HIGH"
            elif score > threshold * 1.0: return "MEDIUM"
        except Exception:
            pass

        return "LOW"

    # ─────────────────────────────────────────────────────────────────────────
    # RAG Context Retrieval
    # ─────────────────────────────────────────────────────────────────────────
    def _get_rag_context(self, query: str) -> str:
        """
        Retrieve context from a trusted knowledge base.

        Represents a "data channel" isolated from the command channel.
        """
        try:
            q_vec = self.embedder.encode(query)
            indices, scores = self.retriever.search(q_vec, k=settings.TOP_K)
            docs = self.retriever.get_docs(indices)
            if not docs:
                return "No relevant context found in the knowledge base."

            # Filtering related results (cosine similarity threshold)
            relevant = [doc for doc, sc in zip(docs, scores) if float(sc) > 0.15]
            selected = relevant if relevant else docs[:2]
            return "\n\n---\n\n".join(selected)
        except Exception as e:
            return f"Context retrieval error: {str(e)}"

    # ────────────────────
    # Main Pipeline
    def run(self, query: str) -> Dict[str, Any]:
        start_time = time.time()
        self._session_stats["total_queries"] += 1

        # Baseline (without defenses) setting for research comparison
        if not self.enable_defenses:
            context  = self._get_rag_context(query)
            response = self.llm.generate_answer(query, context)
            return {
                "response": response, "flag": "baseline",
                "risk": "low", "layer": "none",
                "latency": round(time.time() - start_time, 3)
            }

        try:
            # ── L0: ARS Pre-screening ─────────────────────────────────────────
            risk_level = self._ars_prescreen(query)

            # ── L1: Sanitization + Channel Separation ─────────────────────────
            sanitized_query = sanitize_input(query)
            san_report = get_sanitization_report(query, sanitized_query)

            # If direct injection molding is present
            if san_report["had_template_inj"]:
                return self._block("template_injection", start_time, risk_level)

            # If malicious content is found after sterilization
            if san_report["had_injection"] or san_report["had_base64"]:
                return self._block("sanitization", start_time, risk_level)

            # ── L2: Rule-Based Filter (System Boundary Patterns) ──────────────
            detected, violation_type, rule_risk = rule_based_detector_detailed(sanitized_query)
            if detected:
                block_key = f"rules_{violation_type}" if f"rules_{violation_type}" in BLOCK_MESSAGES else "rules"
                result = self._block(block_key, start_time, rule_risk)
                result["violation_type"] = violation_type
                self._session_stats["by_layer"]["rules"] += 1
                return result

            # ── L3: Anomaly Detection (ARS Full Analysis) ─────────────────────
            anomaly_score = compute_anomaly_score(query)
            threshold     = settings.get_anomaly_threshold()

            # Lower threshold for pre-qualified high-risk inquiries
            effective_threshold = threshold * (0.7 if risk_level == "HIGH" else 1.0)

            if anomaly_score > effective_threshold * 2.0:
                result = self._block("anomaly", start_time, risk_level)
                result["anomaly_score"] = anomaly_score
                self._session_stats["by_layer"]["anomaly"] += 1
                return result

            # ── RAG: Retrieving context from a trusted knowledge base
            context  = self._get_rag_context(sanitized_query)
            response = self.llm.generate_answer(sanitized_query, context)

            # ── L4: Output Guardrailing (Semantic Boundary Check) ─────────────
            # Checks if the response "exceeds the semantic boundaries" of the knowledge base

            # FIXED: L4 used to run only when risk_level was HIGH/MEDIUM.
            # Direct code comparison showed this gate lets attacks the risk
            # sensor doesn't flag (measured: 130/1001 in a sampled batch,
            # 68 of them with a nonzero-but-sub-MEDIUM anomaly score) reach
            # the model with ZERO further checking. L4 stays risk-adaptive
            # (still gated by the L0/L3 risk signal, not "always on" --
            # that would blur the Adaptive Risk Sensor's role) but the
            # definition of "risk-free enough to skip L4" is tightened:
            # LOW now only skips L4 when the anomaly score is genuinely
            # zero across all 6 dimensions, not just under the MEDIUM
            # threshold. A query with ANY detected structural signal, even
            # below the blocking bar, gets the cheap (one embedding +
            # cosine similarity, not a second model call) L4 backstop.
            # Verified this recovers 68/130 (52%) of the previously-leaking
            # attack sample while only touching 14/333 (4.2%) of a fresh
            # benign batch -- vs. 333/333 (100%) if L4 ran unconditionally.
            # NOTE: whether that 4.2% actually gets blocked (not just
            # checked) can only be confirmed with the real model -- re-run
            # diagnose_fpr.py after pulling this.
            if response and (risk_level in ["HIGH", "MEDIUM"] or anomaly_score > 0):
                suspicious, sim_score = semantic_response_is_suspicious(
                    response, self.retriever.get_embeddings(), self.embedder
                )
                if suspicious:
                    result = self._block("semantic", start_time, risk_level)
                    result["similarity_score"] = round(sim_score, 4)
                    self._session_stats["by_layer"]["semantic"] += 1
                    return result

            # ─The query is clean — it passes
            return {
                "response":      response,
                "flag":          "clean",
                "risk":          risk_level.lower(),
                "layer":         "none",
                "anomaly_score": anomaly_score,
                "latency":       round(time.time() - start_time, 3)
            }

        except Exception as e:
            return {
                "response": f"System Error: {str(e)}",
                "flag": "error", "risk": "unknown",
                "layer": "error",
                "latency": round(time.time() - start_time, 3)
            }

    def _block(self, layer: str, start_time: float, risk_level: str) -> Dict[str, Any]:
        self._session_stats["blocked"] += 1
        layer_base = layer.split("_")[0] if "_" in layer else layer
        if layer_base in self._session_stats["by_layer"]:
            self._session_stats["by_layer"][layer_base] += 1

        return {
            "response": BLOCK_MESSAGES.get(layer, f"🛡️ Blocked by layer: {layer}"),
            "flag":     layer_base,
            "layer":    layer,
            "risk":     risk_level.lower(),
            "latency":  round(time.time() - start_time, 3)
        }

    def get_session_stats(self) -> Dict:
        """Session statistics — useful for academic reports"""
        total = self._session_stats["total_queries"]
        blocked = self._session_stats["blocked"]
        return {
            **self._session_stats,
            "block_rate": round(blocked / max(total, 1) * 100, 1),
            "pass_rate":  round((total - blocked) / max(total, 1) * 100, 1),
        }