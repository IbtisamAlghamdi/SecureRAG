#!/usr/bin/env python3
"""
download_enron.py
------------------
Downloads a clean, real-world EMAIL corpus (the original CMU/FERC
public-domain Enron Email Dataset, fetched by DIRECT HTTP DOWNLOAD -- no
API, no auth token, no external SDK) to add to SecureRAG's trusted
knowledge base (data/corpus/), alongside the existing BEIR/NQ (Wikipedia)
corpus. Same download mechanism as download_datasets.py's BEIR fetcher
(urllib.request.urlretrieve against a public URL).

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

Source: original CMU Enron Email Dataset release (public domain, released
during the FERC investigation) --
https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz
(~423 MB compressed, ~1.7 GB uncompressed, ~500K raw email files in
maildir format). Downloaded once and cached in data/downloads/enron/.

Usage:
  python3 download_enron.py            # downloads (~423MB, one-time), samples 1000, writes corpus
  python3 download_enron.py --n 500    # different sample size
  python3 download_enron.py --clean    # delete the cached raw download only
"""

import argparse
import email
import random
import shutil
import sys
import tarfile
import urllib.request
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
DATA_DIR = SCRIPT_DIR / "data"
CORPUS_DIR = DATA_DIR / "corpus"
CACHE_DIR = DATA_DIR / "downloads" / "enron"
ENRON_URL = "https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz"
SEED = 42  # matches build_eval_set.py's SEED -- reproducible sampling

CORPUS_DIR.mkdir(parents=True, exist_ok=True)
CACHE_DIR.mkdir(parents=True, exist_ok=True)

def download_with_progress(url: str, dest: Path):
    print(f"  📥 Downloading from: {url}")

    def progress(count, block_size, total_size):
        if total_size > 0:
            pct = min(count * block_size / total_size * 100, 100)
            bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
            print(f"\r  [{bar}] {pct:.1f}%", end="", flush=True)

    try:
        urllib.request.urlretrieve(url, dest, reporthook=progress)
        print()
        return True
    except Exception as e:
        print(f"\n  ❌ Download failed: {e}")
        return False

def download_tarball() -> Path:
    dest = CACHE_DIR / "enron_mail_20150507.tar.gz"
    if dest.exists():
        print(f"  ⚡ Already downloaded: {dest}")
        return dest

    print(f"  📚 Source: CMU Enron Email Dataset (public domain)")
    print(f"     ~423 MB compressed -- one-time download.")
    ok = download_with_progress(ENRON_URL, dest)
    if not ok:
        print("  ❌ Could not download the Enron dataset. Check your connection.")
        sys.exit(1)
    return dest

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
    tar_path = download_tarball()

    print(f"  📦 Indexing {tar_path.name} (listing ~500K files, can take a minute)...")
    with tarfile.open(tar_path, "r:gz") as tar:
        members = [m for m in tar.getmembers() if m.isfile()]
        print(f"  🔎 {len(members)} raw email files found. Sampling...")

        rng = random.Random(SEED)
        rng.shuffle(members)

        sample_bodies = []
        for m in members:
            if len(sample_bodies) >= n:
                break
            try:
                f = tar.extractfile(m)
                if f is None:
                    continue
                raw = f.read().decode("utf-8", errors="ignore")
            except Exception:
                continue
            body = extract_body(raw)
            # Same floor as extract_corpus_to_txt's BEIR filter (len(text) < 50),
            # plus a ceiling so very long forwarded threads don't dominate.
            if len(body) < 100 or len(body) > 4000:
                continue
            sample_bodies.append(body)

    print(f"  ✅ Sampled {len(sample_bodies)} emails (requested {n})")

    out_path = CORPUS_DIR / "enron_emails_corpus.txt"
    with open(out_path, "w", encoding="utf-8") as out:
        out.write("# Enron Email Dataset Corpus\n")
        out.write("# Source: CMU public-domain release (FERC investigation), direct "
                   "HTTP download, no API --\n")
        out.write("# https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz\n")
        out.write(f"# Sampled: {len(sample_bodies)} real emails, seed={SEED}\n")
        out.write("# NOTE: entirely separate from the BIPIA email documents used in\n")
        out.write("# eval_set.json/fpr_set.json -- no document overlap, avoids leakage.\n\n")
        for body in sample_bodies:
            out.write(body + "\n\n---\n\n")

    print(f"  ✅ Wrote {len(sample_bodies)} emails -> {out_path}")
    return len(sample_bodies)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--n", type=int, default=1000,
                         help="Number of emails to sample into the corpus (default 1000).")
    parser.add_argument("--clean", action="store_true",
                         help="Delete the cached raw download to save disk space "
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
