import os
import sys
import time
from src.config import settings
from src.pipeline import SecureRAG

def check_system_readiness():
    print("\n" + "="*55)
    print("🔍  SYSTEM DIAGNOSTIC CHECK")
    print("="*55)

    # 1. Corpus
    if not os.path.exists(settings.CORPUS_DIR):
        print(f"❌ Corpus Directory NOT FOUND: {settings.CORPUS_DIR}")
    else:
        files = [f for f in os.listdir(settings.CORPUS_DIR) if f.endswith('.txt')]
        status = f"✅ {len(files)} file(s)" if files else "⚠️  EMPTY — add .txt files to get answers!"
        print(f"📂 Corpus ({settings.CORPUS_DIR}): {status}")

    # 2. Vector Index
    index_path = os.path.join(settings.DATA_DIR, "vector_index.faiss")
    if os.path.exists(index_path):
        size_mb = os.path.getsize(index_path) / (1024*1024)
        print(f"✅ Vector Index: FOUND ({size_mb:.1f} MB)")
    else:
        print(f"⚠️  Vector Index: Will be built on first run")

    # 3. Models
    print("\n🤖 Models Status:")
    for name, cfg in settings.MODELS_CONFIG.items():
        path = os.path.join(settings.MODELS_DIR, cfg['file'])
        status = "✅ Ready" if os.path.exists(path) else "❌ Not Downloaded"
        print(f"   {name:20s} ({cfg['type']:16s}) — {status}")

    print("="*55 + "\n")

def select_model():
    models = list(settings.MODELS_CONFIG.keys())
    print("\n🤖 Select a model:")
    for i, name in enumerate(models):
        path = os.path.join(settings.MODELS_DIR, settings.MODELS_CONFIG[name]['file'])
        status = "✅" if os.path.exists(path) else "❌"
        print(f"  {i+1}. {status} {name} ({settings.MODELS_CONFIG[name]['type']})")

    choice = input("\nModel number (default 3 = Mistral-7B): ").strip()
    idx = int(choice) - 1 if choice.isdigit() and 0 < int(choice) <= len(models) else 2

    selected = models[idx]
    settings.GGUF_FILE = settings.MODELS_CONFIG[selected]["file"]
    settings.LLM_MODEL_PATH = os.path.join(settings.MODELS_DIR, settings.GGUF_FILE)

    if not os.path.exists(settings.LLM_MODEL_PATH):
        print(f"\n❌ Model not found: {settings.LLM_MODEL_PATH}")
        print("👉 Run: python3 download_models.py")
        sys.exit(1)

    return selected

def start_chat():
    print("\n" + "="*60)
    print("🛡️   SecureRAG — Multi-Layered Adaptive Defense Framework")
    print("="*60)
    print("🚀 Version: V7 | Embedding: sentence-transformers (MiniLM-L6)")

    check_system_readiness()
    selected_model = select_model()
    print(f"\n🔄 Initializing {selected_model}...")

    try:
        rag = SecureRAG(enable_defenses=True)
    except Exception as e:
        print(f"❌ Initialization Error: {e}")
        import traceback; traceback.print_exc()
        return

    print("\nType 'exit' to quit  |  Type 'help' for commands. Mode: SECURE\n")

    while True:
        try:
            query = input("👤 User: ").strip()
            if not query:
                continue
            if query.lower() in ['exit', 'quit']:
                print("👋 Goodbye!")
                break
            if query.lower() == 'help':
                print("  Commands: exit | help")
                print("  Ask any question about topics covered in your corpus files.")
                continue

            print("⏳ Thinking...", end="\r")
            result = rag.run(query)
            print(" " * 20, end="\r")

            risk_icon = {"low": "🟢 LOW", "medium": "🟡 MEDIUM",
                         "high": "🔴 HIGH"}.get(result['risk'], result['risk'].upper())

            if result['flag'] in ['clean', 'baseline']:
                print(f"🤖 Assistant: {result['response']}")
                print(f"   [✅ SAFE | Risk: {risk_icon} | {result['latency']:.2f}s | {selected_model}]")
            else:
                print(f"🛡️  System: {result['response']}")
                print(f"   [🛡️ BLOCKED | Layer: {result['flag'].upper()} | Risk: {risk_icon} | {result['latency']:.2f}s]")

        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    start_chat()
