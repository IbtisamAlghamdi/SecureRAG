import os
import faiss
import json
import numpy as np
from src.rag_core.embeddings.embedder import Embedder
from src.config import settings

class FaissRetriever:
    def __init__(self, corpus_path: str, embedder: Embedder):
        self.corpus_path = corpus_path
        self.embedder = embedder

        self.index_path = os.path.join(settings.DATA_DIR, "vector_index.faiss")
        self.docs_path  = os.path.join(settings.DATA_DIR, "docs_cache.json")
        self.embs_path  = os.path.join(settings.DATA_DIR, "embs_cache.npy")

        os.makedirs(settings.DATA_DIR, exist_ok=True)

        if self._cache_exists():
            print("⚡ Loading existing FAISS index...")
            try:
                self.index = faiss.read_index(self.index_path)
                with open(self.docs_path, "r", encoding="utf-8") as f:
                    self.documents = json.load(f)
                self.embeddings = np.load(self.embs_path)
                print(f"✅ FAISS index loaded: {len(self.documents)} chunks.")
            except Exception as e:
                print(f"⚠️ Cache corrupted ({e}). Re-indexing...")
                self._fresh_index()
        else:
            self._fresh_index()

    def _fresh_index(self):
        print("🔍 Building fresh FAISS index from corpus...")
        self.documents = self._load_corpus()
        self.embeddings = self._build_embeddings()
        self.index = self._build_index()
        self._save_cache()

    def _cache_exists(self) -> bool:
        return all(os.path.exists(p) for p in [self.index_path, self.docs_path, self.embs_path])

    def _save_cache(self):
        try:
            faiss.write_index(self.index, self.index_path)
            with open(self.docs_path, "w", encoding="utf-8") as f:
                json.dump(self.documents, f, ensure_ascii=False)
            np.save(self.embs_path, self.embeddings)
            print(f"💾 Index saved to {settings.DATA_DIR}")
        except Exception as e:
            print(f"⚠️ Error saving cache: {e}")

    def _load_corpus(self) -> list:
        docs = []
        if not os.path.exists(self.corpus_path):
            os.makedirs(self.corpus_path, exist_ok=True)

        files = sorted([f for f in os.listdir(self.corpus_path) if f.endswith(".txt")])
        if not files:
            print("⚠️ No .txt files found in corpus directory!")
            return ["Empty corpus placeholder."]

        print(f"📂 Found {len(files)} files in corpus. Loading...")
        for fname in files:
            try:
                fpath = os.path.join(self.corpus_path, fname)
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().strip()
                if not content:
                    continue
                # Smart chunking مع overlap
                step = settings.CHUNK_SIZE - settings.CHUNK_OVERLAP
                chunks = [content[i:i + settings.CHUNK_SIZE]
                          for i in range(0, len(content), step)]
                # Filter very short chunks
                chunks = [c for c in chunks if len(c.split()) >= 10]
                docs.extend(chunks)
            except Exception as e:
                print(f"⚠️ Error reading {fname}: {e}")

        print(f"✅ Total chunks created: {len(docs)}")
        return docs if docs else ["Empty corpus placeholder."]

    def _build_embeddings(self) -> np.ndarray:
        print(f"📦 Embedding {len(self.documents)} chunks (one-time operation)...")
        embs = self.embedder.encode_many(self.documents)
        return embs.astype('float32')

    def _build_index(self):
        if self.embeddings.size == 0:
            return faiss.IndexFlatIP(384)  # Inner Product (للـ normalized vectors)

        dim = self.embeddings.shape[1]
        # IndexFlatIP performs best with normalized embeddings (cosine similarity).
        index = faiss.IndexFlatIP(dim)
        index.add(self.embeddings)
        print(f"✅ FAISS index ready: {len(self.documents)} vectors, dim={dim}")
        return index

    def search(self, query_vec: np.ndarray, k: int = 5):
        if self.index is None or len(self.documents) == 0:
            return [], []
        q_vec = query_vec.reshape(1, -1).astype('float32')
        k = min(k, len(self.documents))
        scores, indices = self.index.search(q_vec, k)
        return indices[0], scores[0]

    def get_docs(self, indices) -> list:
        return [self.documents[i] for i in indices if 0 <= i < len(self.documents)]

    def get_embeddings(self) -> np.ndarray:
        return self.embeddings
