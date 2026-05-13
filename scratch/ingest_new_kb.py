import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ingest import load_all_documents
from components import build_store

def main():
    print("Starting ingestion process...")
    
    # Force re-ingestion to ensure new documents are added
    os.environ["FORCE_REINGEST"] = "true"
    
    # Load all documents (including the new ADAS domain KB)
    all_docs = load_all_documents()
    
    # Build store and upload to Weaviate
    store, embedder = build_store(all_docs)
    
    print("\nIngestion complete!")
    print(f"Total documents in Weaviate: {store.count_documents()}")

if __name__ == "__main__":
    main()
