"""Dataset Downloader for SecureRAG ================================= It loads and prepares academic datasets: 1."""

import os
import json
import argparse
import urllib.request
import zipfile
import shutil
from pathlib import Path

# ─── Paths 
BASE_DIR    = Path(__file__).parent
DATA_DIR    = BASE_DIR / "data"
CORPUS_DIR  = DATA_DIR / "corpus"
CACHE_DIR   = DATA_DIR / "downloads"

CORPUS_DIR.mkdir(parents=True, exist_ok=True)
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# ─── BEIR official links 
BEIR_BASE = "https://public.ukp.informatik.tu-darmstadt.de/thakur/BEIR/datasets"

DATASETS = {
    "nq": {
        "url":         f"{BEIR_BASE}/nq.zip",
        "description": "Natural Questions — real Google queries answered from Wikipedia",
        "paper":       "Kwiatkowski et al. (2019), used in PoisonedRAG USENIX 2025",
        "size":        "~3.5 MB (test split)",
        "max_docs":    500,   # We take the first 500 documents for the corpus
        "max_queries": 100,   # We take the first 100 questions as benign queries
    },
    "scifact": {
        "url":         f"{BEIR_BASE}/scifact.zip",
        "description": "Scientific fact-checking — claim verification from research papers",
        "paper":       "Wadden et al. (2020), used in BEIR benchmark NeurIPS 2021",
        "size":        "~1.5 MB",
        "max_docs":    300,
        "max_queries": 100,
    },
    "fiqa": {
        "url":         f"{BEIR_BASE}/fiqa.zip",
        "description": "Financial QA — questions from finance forums",
        "paper":       "Maia et al. (2018), used in BEIR benchmark",
        "size":        "~2 MB",
        "max_docs":    300,
        "max_queries": 100,
    },
}

def download_with_progress(url: str, dest: Path):
    """Download with a simple progress bar"""
    print(f"  📥 Downloading from: {url}")

    def progress(count, block_size, total_size):
        if total_size > 0:
            pct = min(count * block_size / total_size * 100, 100)
            bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
            print(f"\r  [{bar}] {pct:.1f}%", end="", flush=True)

    try:
        urllib.request.urlretrieve(url, dest, reporthook=progress)
        print()  #newline after the progress bar
        return True
    except Exception as e:
        print(f"\n  ❌ Download failed: {e}")
        return False

def extract_corpus_to_txt(dataset_name: str, data_path: Path,
                           max_docs: int, max_queries: int):
    """It extracts documents and questions from BEIR format and converts them to .txt files into the."""
    corpus_file  = data_path / "corpus.jsonl"
    queries_file = data_path / "queries.jsonl"

    if not corpus_file.exists():
        print(f"  ❌ corpus.jsonl not found in {data_path}")
        return 0, 0

    #document conversion
    docs_saved = 0
    out_corpus = CORPUS_DIR / f"beir_{dataset_name}_corpus.txt"

    with open(corpus_file, "r", encoding="utf-8") as f, \
         open(out_corpus, "w", encoding="utf-8") as out:

        out.write(f"# BEIR/{dataset_name.upper()} Corpus\n")
        out.write(f"# Source: Thakur et al. (2021) BEIR Benchmark — NeurIPS 2021\n")
        out.write(f"# Used in: PoisonedRAG (USENIX 2025), RAG Security Research\n\n")

        for line in f:
            if docs_saved >= max_docs:
                break
            try:
                doc = json.loads(line.strip())
                title = doc.get("title", "").strip()
                text  = doc.get("text", "").strip()
                if len(text) < 50:  # Skip very short documents
                    continue
                if title:
                    out.write(f"## {title}\n{text}\n\n")
                else:
                    out.write(f"{text}\n\n")
                docs_saved += 1
            except:
                continue

    print(f"  ✅ Corpus: {docs_saved} documents → {out_corpus.name}")

    # Transforming questions (Benign Queries for Assessment)
    queries_saved = 0
    if queries_file.exists():
        out_queries = DATA_DIR / f"beir_{dataset_name}_queries.txt"
        with open(queries_file, "r", encoding="utf-8") as f, \
             open(out_queries, "w", encoding="utf-8") as out:
            for line in f:
                if queries_saved >= max_queries:
                    break
                try:
                    q = json.loads(line.strip())
                    text = q.get("text", "").strip()
                    if text:
                        out.write(text + "\n")
                        queries_saved += 1
                except:
                    continue
        print(f"  ✅ Queries: {queries_saved} benign queries → {out_queries.name}")

    return docs_saved, queries_saved

def download_dataset(name: str):
    """Download and prepare the complete dataset"""
    if name not in DATASETS:
        print(f"❌ Unknown dataset: {name}. Available: {list(DATASETS.keys())}")
        return False

    cfg = DATASETS[name]
    print(f"\n{'='*60}")
    print(f"📚 Dataset: BEIR/{name.upper()}")
    print(f"   {cfg['description']}")
    print(f"   Paper: {cfg['paper']}")
    print(f"   Size: {cfg['size']}")
    print(f"{'='*60}")

    # Check if it's pre-loaded
    zip_path  = CACHE_DIR / f"{name}.zip"
    data_path = CACHE_DIR / name

    if (CORPUS_DIR / f"beir_{name}_corpus.txt").exists():
        print(f"  ⚡ Already downloaded. Skipping.")
        return True

    # download
    if not zip_path.exists():
        success = download_with_progress(cfg["url"], zip_path)
        if not success:
            return False
    else:
        print(f"  ⚡ ZIP already cached.")

    # Unzip
    if not data_path.exists():
        print(f"  📦 Extracting...")
        try:
            with zipfile.ZipFile(zip_path, 'r') as z:
                z.extractall(CACHE_DIR)
            print(f"  ✅ Extracted to {data_path}")
        except Exception as e:
            print(f"  ❌ Extraction failed: {e}")
            return False

    # Convert to corpus
    print(f"  🔄 Converting to SecureRAG corpus format...")
    docs, queries = extract_corpus_to_txt(
        name, data_path,
        max_docs=cfg["max_docs"],
        max_queries=cfg["max_queries"]
    )

    return docs > 0

def show_corpus_status():
    """Display the current corpus status"""
    print(f"\n{'='*60}")
    print(f"📂 CORPUS STATUS: {CORPUS_DIR}")
    print(f"{'='*60}")

    txt_files = list(CORPUS_DIR.glob("*.txt"))
    if not txt_files:
        print("  ⚠️  No corpus files found!")
    else:
        total_size = 0
        for f in sorted(txt_files):
            size = f.stat().st_size
            total_size += size
            lines = sum(1 for _ in open(f, encoding="utf-8", errors="ignore"))
            print(f"  📄 {f.name:<40} {size/1024:>6.1f} KB  ({lines} lines)")
        print(f"  {'─'*55}")
        print(f"  Total: {len(txt_files)} files, {total_size/1024:.1f} KB")

    # BEIR Questions
    query_files = list(DATA_DIR.glob("beir_*_queries.txt"))
    if query_files:
        print(f"\n📋 BEIR QUERY FILES (for evaluation):")
        for f in query_files:
            count = sum(1 for _ in open(f, encoding="utf-8", errors="ignore"))
            print(f"  📋 {f.name:<40} {count} queries")

    print(f"{'='*60}\n")

def delete_cache():
    """Delete the cache to free up space"""
    if CACHE_DIR.exists():
        shutil.rmtree(CACHE_DIR)
        print(f"🗑️  Cache deleted: {CACHE_DIR}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Download BEIR datasets for SecureRAG",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 download_datasets.py --dataset nq
  python3 download_datasets.py --dataset scifact
  python3 download_datasets.py --all
  python3 download_datasets.py --status
  python3 download_datasets.py --clean
        """
    )
    parser.add_argument("--dataset", choices=list(DATASETS.keys()),
                        help="Download a specific dataset")
    parser.add_argument("--all",    action="store_true",
                        help="Download all datasets")
    parser.add_argument("--status", action="store_true",
                        help="Show current corpus status")
    parser.add_argument("--clean",  action="store_true",
                        help="Delete download cache (saves disk space)")
    args = parser.parse_args()

    if args.status:
        show_corpus_status()

    elif args.clean:
        delete_cache()

    elif args.all:
        results = {}
        for name in DATASETS:
            results[name] = download_dataset(name)
        print(f"\n{'='*60}")
        print("📊 DOWNLOAD SUMMARY:")
        for name, ok in results.items():
            print(f"  {'✅' if ok else '❌'} BEIR/{name.upper()}")
        # Delete the cache after conversion to save space
        delete_cache()
        show_corpus_status()

    elif args.dataset:
        ok = download_dataset(args.dataset)
        if ok:
            delete_cache() 
            show_corpus_status()
            print(f"\n🎉 Done! Now delete old FAISS cache and restart:")
            print(f"   rm -f data/vector_index.faiss data/docs_cache.json data/embs_cache.npy")
            print(f"   python3 chat.py")
        else:
            print(f"\n❌ Download failed. Check your internet connection.")

    else:
        parser.print_help()
        print(f"\n")
        show_corpus_status()
