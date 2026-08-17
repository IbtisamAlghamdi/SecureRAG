import os
from src.config import settings

try:
    from llama_cpp import Llama
except ImportError:
    Llama = None

class LLMEngine:
    """Generator engine using GGUF - Singleton"""
    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(LLMEngine, cls).__new__(cls)
        return cls._instance

    def __init__(self, model_path: str = None):
        if self._initialized:
            return

        self.model_path = model_path or os.path.join(settings.MODELS_DIR, settings.GGUF_FILE)
        self.temp         = getattr(settings, 'TEMPERATURE', 0.7)
        self.top_p        = getattr(settings, 'TOP_P', 0.9)
        self.top_k        = getattr(settings, 'TOP_K_LLM', 40)
        self.repeat_penalty = getattr(settings, 'REPETITION_PENALTY', 1.1)
        self.max_tokens   = getattr(settings, 'MAX_NEW_TOKENS', 512)

        if Llama is None:
            print("❌ llama-cpp-python is not installed.")
            self.llm = None
            return

        if not os.path.exists(self.model_path):
            print(f"❌ Model not found: {self.model_path}")
            print("👉 Run: python3 download_models.py")
            self.llm = None
            return

        try:
            print(f"🚀 Loading LLM: {os.path.basename(self.model_path)}...")
            self.llm = Llama(
                model_path=self.model_path,
                n_ctx=getattr(settings, 'N_CTX', 4096),
                n_threads=getattr(settings, 'N_THREADS', 8),
                verbose=False,
                n_gpu_layers=-1
            )
            LLMEngine._initialized = True
            print("✅ LLM loaded successfully.")
        except Exception as e:
            print(f"❌ Failed to load LLM: {e}")
            self.llm = None

    def generate_answer(self, query: str, context: str) -> str:
        if self.llm is None:
            return "Error: LLM not initialized. Check model path and run download_models.py."

        # Clean context of empty text
        context = context.strip() if context else "No relevant context found."
        prompt = settings.ANSWER_PROMPT_TEMPLATE.format(query=query, context=context)

        try:
            output = self.llm(
                prompt,
                max_tokens=self.max_tokens,
                temperature=self.temp,
                top_p=self.top_p,
                repeat_penalty=self.repeat_penalty,
                stop=["</s>", "[/INST]", "Question:", "User:"],
                echo=False
            )
            answer = output['choices'][0]['text'].strip()
            return answer if answer else "I could not generate a response. Please try again."
        except Exception as e:
            return f"Generation Error: {str(e)}"
