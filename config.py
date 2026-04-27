# =============================================================================
# config.py — Central configuration for TARA RAG pipeline
# =============================================================================

from pathlib import Path

# ---------------------------------------------------------------------------
# Base dataset directory (relative to this file's location)
# ---------------------------------------------------------------------------
BASE_PATH    = Path(__file__).parent / "datasets"

MITRE_MOBILE = BASE_PATH / "mobileattack.json"
MITRE_ICS    = BASE_PATH / "icsattack.json"
ATM_PATH     = BASE_PATH / "atm.json"
CAPEC_PATH   = BASE_PATH / "capec.xml"
CWE_PATH     = BASE_PATH / "cwec.xml"
ECU_PATH     = BASE_PATH / "dataecu.json"
ANNEX_PATH   = BASE_PATH / "annex.json"
CLAUSE_PATH  = BASE_PATH / "clauses"
REPORTS_PATH = BASE_PATH / "reports_db"
SECURITY_KB_PATH = BASE_PATH / "security_KB"
PDF_PATH     = BASE_PATH


# ---------------------------------------------------------------------------
# Embedding model
# BGE-small beats MiniLM on BEIR benchmarks at same size
# ---------------------------------------------------------------------------
EMBED_MODEL = "BAAI/bge-small-en-v1.5"
# Fallback: "sentence-transformers/all-MiniLM-L6-v2"

# ---------------------------------------------------------------------------
# Re-ranking (Cross-Encoder)
# ---------------------------------------------------------------------------
RANKER_MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"
TOP_K_RANKER = 10

# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------
MAX_CHARS = 1500   # max chars per chunk for threat-framework entries

# ---------------------------------------------------------------------------
# LLM
# ---------------------------------------------------------------------------
GEMINI_MODEL = "gemini-2.5-flash-lite" 

# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------
RETRIEVER_TOP_K = 50  # Coverage

# ---------------------------------------------------------------------------
# Vector DB (Weaviate)
# ---------------------------------------------------------------------------
WEAVIATE_URL = "https://5uc6g0vjt8ax2yyl1kcdvq.c0.asia-southeast1.gcp.weaviate.cloud"
WEAVIATE_API_KEY = "dHR1b0U3dW81WmQ4eU01N18xZXlyWkRTSXUvdHdWaTlQWExoVUtuWEJqWUFYdUhjWVRLRzAxbGVtcks0PV92MjAw"
WEAVIATE_COLLECTION = "HaystackDocument"
