import numpy as np

try:
    from sentence_transformers import SentenceTransformer
    ST_AVAILABLE = True
except ImportError:
    ST_AVAILABLE = False

class Embedder:
    """Embeddings engine using sentence-transformers (all-MiniLM-L6-v2) Custom model for semantic."""
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Embedder, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        if not ST_AVAILABLE:
            print("❌ sentence-transformers is not installed. Run: pip install sentence-transformers")
            self.model = None
            self.dim = 384
            return

        print("🔄 Loading Embedding Engine (all-MiniLM-L6-v2)...")
        try:
            self.model = SentenceTransformer('all-MiniLM-L6-v2')
            self.dim = 384
            self._initialized = True
            print("✅ Embedding Engine loaded. (dim=384)")
        except Exception as e:
            print(f"❌ Failed to load embedding model: {e}")
            self.model = None
            self.dim = 384

    def encode(self, text: str) -> np.ndarray:
        if self.model is None:
            return np.zeros(self.dim, dtype=np.float32)
        try:
            vec = self.model.encode(text.replace("\n", " ").strip(),
                                    convert_to_numpy=True, normalize_embeddings=True)
            return vec.astype(np.float32)
        except Exception as e:
            print(f"Embedding Error: {e}")
            return np.zeros(self.dim, dtype=np.float32)

    def encode_many(self, texts: list) -> np.ndarray:
        if self.model is None:
            return np.zeros((len(texts), self.dim), dtype=np.float32)
        try:
            embs = self.model.encode(texts, convert_to_numpy=True,
                                     normalize_embeddings=True, batch_size=32,
                                     show_progress_bar=len(texts) > 50)
            return embs.astype(np.float32)
        except Exception as e:
            return np.array([self.encode(t) for t in texts], dtype=np.float32)
