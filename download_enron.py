#!/usr/bin/env python3
"""
download_enron.py
------------------
Downloads a clean, real-world EMAIL corpus (Enron Email Dataset, Kaggle
mirror of the original CMU/FERC public-domain corpus) to add to
SecureRAG's trusted knowledge base (data/corpus/), alongside the existing
BEIR/NQ (Wikipedia) corpus.

WHY: SecureRAG's external validation set (eval_set.json / fpr_set.json)
is built from BIPIA (Microsoft) email/table documents. L4's semantic
guardrail (semantic_response_is_suspicious) checks the model's response
against data/corpus/'s embeddings -- comparing an answer ABOUT an email
to a corpus of Wikipedia articles is an apples-to-oranges comparison that
produced noisy, non-discriminating similarity scores (root-caused via the
diagnostic columns in run_external_eval.py / run_external_fpr_eval.py).
Adding a domain-matched but ENTIRELY SEPARATE corpus (no document overlap
with the BIPIA emails used in eval_set.json/fpr_set.json) gives L4 a
meaningful reference space for email-style content.

Source: Kaggle mirror of the CMU Enron Email Dataset (public domain,
released during the FERC investigation) --
https://www.kaggle.com/datasets/wcukierski/enron-email-dataset

Requires the Kaggle CLI + API token (one-time setup):
  pip install kaggle
  # Get your token: https://www.kaggle.com/settings -> API -> Create New Token
  # Save the downloaded kaggle.json to ~/.kaggle/kaggle.json, then:
  chmod 600 ~/.kaggle/kaggle.json

Usage:
  python3 download_enron.py            # downloads, samples 1000, writes corpus
  python3 download_enron.py --n 500    # different sample size
  python3 download_enron.py --clean    # delete the cached raw download only
"""

import argparse
import csv
import email
import io
import random
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
DATA_DIR = SCRIPT_DIR / "data"
CORPUS_DIR = DATA_DIR / "corpus"
CACHE_DIR = DATA_DIR / "downloads" / "enron"
KAGGLE_DATASET = "wcukierski/enron-email-dataset"
SEED = 42  # matches build_eval_set.py's SEED -- reproducible sampling

CORPUS_DIR.mkdir(parents=True, exist_ok=True)
CACHE_DIR.mkdir(parents=True, exist_ok=True)


def download_via_kaggle() -> Path:
    existing = list(CACHE_DIR.glob("*.zip"))
    if existing:
        print(f"  ⚡ Already downloaded: {existing[0]}")
        return existing[0]

    print(f"  📥 Downloading via Kaggle CLI: {KAGGLE_DATASET}")
    try:
        subprocess.run(
            ["kaggle", "datasets", "download", "-d", KAGGLE_DATASET,
             "-p", str(CACHE_DIR)],
            check=True,
        )
    except FileNotFoundError:
        print("\n  ❌ 'kaggle' CLI not found. Install it first:")
        print("       pip install kaggle")
        print("     Then get your API token from https://www.kaggle.com/settings")
        print("     -> API -> Create New Token, save as ~/.kaggle/kaggle.json")
        print("     chmod 600 ~/.kaggle/kaggle.json")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"\n  ❌ Kaggle download failed: {e}")
        print("     Check that ~/.kaggle/kaggle.json exists and is valid, and that")
        print("     you've accepted the dataset's terms once on kaggle.com.")
        sys.exit(1)

    zips = list(CACHE_DIR.glob("*.zip"))
    if not zips:
        print("  ❌ No .zip found after download.")
        sys.exit(1)
    return zips[0]


def extract_body(raw_message: str) -> str:
    """Parse one Enron RFC822-style message and return just the body text."""
    try:
        msg = email.message_from_string(raw_message)
        if msg.is_multipart():
            parts = [p.get_payload(decode=False) for p in msg.walk()
                     if p.get_content_type() == "text/plain"]
            body = "\n".join(p for p in parts if p)
        else:
            body = msg.get_payload()
        return (body or "").strip()
    except Exception:
        return ""


def build_corpus(n: int):
    zip_path = download_via_kaggle()

    print(f"  📦 Reading {zip_path.name}...")
    with zipfile.ZipFile(zip_path) as z:
        csv_name = next((name for name in z.namelist() if name.endswith(".csv")), None)
        if not csv_name:
            print("  ❌ No CSV found inside the Kaggle zip.")
            sys.exit(1)

        candidates = []
        with z.open(csv_name) as raw:
            text_stream = io.TextIOWrapper(raw, encoding="utf-8", errors="ignore")
            reader = csv.DictReader(text_stream)
            for row in reader:
                body = extract_body(row.get("message", ""))
                # Same floor as extract_corpus_to_txt's BEIR filter (len(text) < 50),
                # plus a ceiling so very long forwarded threads don't dominate.
                if len(body) < 100 or len(body) > 4000:
                    continue
                candidates.append(body)
                if len(candidates) >= n * 20:
                    # Enough of a pool to sample from without reading all ~500K rows.
                    break

    print(f"  🔎 Pool of {len(candidates)} candidate emails, sampling {n}...")
    rng = random.Random(SEED)
    sample = rng.sample(candidates, min(n, len(candidates)))

    out_path = CORPUS_DIR / "enron_emails_corpus.txt"
    with open(out_path, "w", encoding="utf-8") as out:
        out.write("# Enron Email Dataset Corpus\n")
        out.write("# Source: CMU/FERC public-domain release, Kaggle mirror "
                   "(wcukierski/enron-email-dataset)\n")
        out.write(f"# Sampled: {len(sample)} real emails, seed={SEED}\n")
        out.write("# NOTE: entirely separate from the BIPIA email documents used in\n")
        out.write("# eval_set.json/fpr_set.json -- no document overlap, avoids leakage.\n\n")
        for body in sample:
            out.write(body + "\n\n---\n\n")

    print(f"  ✅ Wrote {len(sample)} emails -> {out_path}")
    return len(sample)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--n", type=int, default=1000,
                         help="Number of emails to sample into the corpus (default 1000).")
    parser.add_argument("--clean", action="store_true",
                         help="Delete the cached raw Kaggle download to save disk space "
                              "(keeps the already-written corpus .txt file).")
    args = parser.parse_args()

    if args.clean:
        if CACHE_DIR.exists():
            shutil.rmtree(CACHE_DIR)
            print(f"🗑️  Cache deleted: {CACHE_DIR}")
        sys.exit(0)

    n_written = build_corpus(args.n)
    print(f"\n🎉 Done! Now delete the old FAISS cache and restart so the new corpus "
          f"gets indexed:")
    print(f"   rm -f data/vector_index.faiss data/docs_cache.json data/embs_cache.npy")
    print(f"   python3 chat.py")
