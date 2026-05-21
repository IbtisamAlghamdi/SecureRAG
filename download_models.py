import os
import requests
from tqdm import tqdm
from src.config import settings

def download_file(url, filename):
    """Upload file with progress bar displayed"""
    path = os.path.join(settings.MODELS_DIR, filename)
    if os.path.exists(path):
        print(f"✅ {filename} already exists. Skipping.")
        return

    print(f"📥 Downloading {filename}...")
    response = requests.get(url, stream=True)
    total_size = int(response.headers.get('content-length', 0))
    
    with open(path, 'wb') as file, tqdm(
        desc=filename,
        total=total_size,
        unit='iB',
        unit_scale=True,
        unit_divisor=1024,
    ) as bar:
        for data in response.iter_content(chunk_size=1024):
            size = file.write(data)
            bar.update(size)

def main():
    print("🤖 Model Downloader for Multi-Model Evaluation (SIGIR '25 Style)")
    print("="*60)
    
    for name, config in settings.MODELS_CONFIG.items():
        print(f"\nModel: {name} ({config['type']})")
        try:
            download_file(config['url'], config['file'])
        except Exception as e:
            print(f"❌ Error downloading {name}: {e}")
            print("Please check your internet connection or the URL.")

    print("\n" + "="*60)
    print("✅ All selected models are ready in the 'models/' directory.")

if __name__ == "__main__":
    main()
