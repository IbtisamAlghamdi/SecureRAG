"""
model_select.py
-----------------
Shared model-selection helper used by every entry point (chat.py,
thesis_evaluation.py, test_scenarios.py, diagnose_fpr.py,
run_external_eval.py, run_external_fpr_eval.py) so there is ONE place that
decides which of your downloaded GGUF models a run uses -- instead of each
script re-implementing its own prompt (which is how thesis_evaluation.py
ended up with no model choice at all before).

Guarantee this exists to satisfy: switching models changes ONLY
settings.GGUF_FILE / settings.LLM_MODEL_PATH (which file LLMEngine loads).
Every other setting -- thresholds, chunk size, corpus, prompt template,
generation params -- comes from settings.py exactly the same way no matter
which model is selected, so a run with model A vs model B differs ONLY in
the model. See src/pipeline.py::SecureRAG(model_path=...) and
src/rag_core/generation/llm_engine.py for how that is enforced.

Two ways to pick a model:

1. Non-interactive (recommended for evaluation scripts, since a 5-seed run
   takes hours and you don't want to babysit a prompt):
       python3 thesis_evaluation.py --model Mistral-7B
       python3 thesis_evaluation.py --model Llama-3.2-3B
       python3 thesis_evaluation.py --model Phi-3.5-Mini

2. Interactive (same experience as chat.py already had):
       python3 thesis_evaluation.py
       -> prompts "Select a model: 1/2/3 ..."

Model names are exactly the keys of settings.MODELS_CONFIG.
"""

import argparse
import os
import sys

from src.config import settings

def add_model_arg(parser: argparse.ArgumentParser) -> None:
    """Attach `--model NAME` to an argparse parser."""
    parser.add_argument(
        "--model",
        choices=list(settings.MODELS_CONFIG.keys()),
        default=None,
        help="Which downloaded GGUF model to evaluate. If omitted, you "
             "will be prompted interactively. Choices: "
             + ", ".join(settings.MODELS_CONFIG.keys()),
    )

def _prompt_interactively() -> str:
    models = list(settings.MODELS_CONFIG.keys())
    print("\n🤖 Select a model:")
    for i, name in enumerate(models):
        path = os.path.join(settings.MODELS_DIR, settings.MODELS_CONFIG[name]["file"])
        status = "✅" if os.path.exists(path) else "❌"
        print(f"  {i + 1}. {status} {name} ({settings.MODELS_CONFIG[name]['type']})")

    default_idx = models.index("Mistral-7B") if "Mistral-7B" in models else 0
    choice = input(f"\nModel number (default {default_idx + 1} = {models[default_idx]}): ").strip()
    idx = int(choice) - 1 if choice.isdigit() and 0 < int(choice) <= len(models) else default_idx
    return models[idx]

def resolve_model(name: str = None) -> str:
    """Given a model name (already validated by argparse `choices`, or None), return the model name to."""
    selected = name or _prompt_interactively()

    if selected not in settings.MODELS_CONFIG:
        print(f"❌ Unknown model '{selected}'. Choices: {list(settings.MODELS_CONFIG.keys())}")
        sys.exit(1)

    settings.GGUF_FILE = settings.MODELS_CONFIG[selected]["file"]
    settings.LLM_MODEL_PATH = os.path.join(settings.MODELS_DIR, settings.GGUF_FILE)

    if not os.path.exists(settings.LLM_MODEL_PATH):
        print(f"\n❌ Model not found: {settings.LLM_MODEL_PATH}")
        print("👉 Place the .gguf file in models/, or run: python3 download_models.py")
        sys.exit(1)

    return selected

def model_path_for(name: str) -> str:
    """Absolute path for a given model name, without touching settings or prompting."""
    if name not in settings.MODELS_CONFIG:
        raise ValueError(f"Unknown model '{name}'. Choices: {list(settings.MODELS_CONFIG.keys())}")
    return os.path.join(settings.MODELS_DIR, settings.MODELS_CONFIG[name]["file"])

def safe_filename(model_name: str) -> str:
    """Model name -> filesystem-safe suffix for per-model output files, e.g."""
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in model_name)
