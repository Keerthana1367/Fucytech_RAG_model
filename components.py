# =============================================================================
# components.py — Config, ECU resolution, UUID post-processing, component setup
# =============================================================================

import json
import os
import re
import uuid as _uuid
from pathlib import Path

from haystack.components.embedders import (
    SentenceTransformersDocumentEmbedder,
    SentenceTransformersTextEmbedder,
)
from haystack.components.rankers import SentenceTransformersSimilarityRanker
from haystack.document_stores.types import DuplicatePolicy
from haystack.utils import Secret
from haystack_integrations.document_stores.weaviate import WeaviateDocumentStore
from haystack_integrations.document_stores.weaviate.auth import AuthApiKey
from haystack_integrations.components.retrievers.weaviate import WeaviateEmbeddingRetriever
from haystack_integrations.components.generators.google_ai import GoogleAIGeminiGenerator
import weaviate
from weaviate.classes.init import AdditionalConfig, Timeout


from config import (
    EMBED_MODEL, MAX_CHARS, GEMINI_MODEL, RETRIEVER_TOP_K,
    WEAVIATE_URL, WEAVIATE_API_KEY, WEAVIATE_COLLECTION,
    MITRE_MOBILE, MITRE_ICS, ATM_PATH, CAPEC_PATH, CWE_PATH,
    ECU_PATH, ANNEX_PATH, CLAUSE_PATH, REPORTS_PATH, PDF_PATH,
    RANKER_MODEL, TOP_K_RANKER
)



# ─────────────────────────────────────────────────────────────────────────────
# ECU RESOLUTION
# ─────────────────────────────────────────────────────────────────────────────

_SUFFIX_WORDS = {
    "ecu", "system", "module", "interface", "controller", "unit",
    "network", "port", "server", "bus", "head", "vehicle", "automotive"
}

_ALIASES = {
    "obd":               "obd",
    "obd-ii":            "obd",
    "obd2":              "obd",
    "tcu":               "tcu",
    "telematics control":"tcu",
    "bcm":               "bcm",
    "ecm":               "ecm",
    "ivi":               "ivi",
    "eps":               "eps",
    "abs":               "abs",
    "bms":               "bms",
    "adas":              "adas",
}


def _acronym(text: str) -> str:
    skip      = {"the", "and", "for", "of", "a", "an", "or", "in", "on", "to", "/"}
    words     = [w.strip("()/-").lower() for w in text.replace("/", " ").split()]
    sig_words = [w for w in words if w and w not in skip]
    core      = [w for w in sig_words if w not in _SUFFIX_WORDS]
    chosen    = core if core else sig_words
    return "".join(w[0] for w in chosen if w)


def resolve_ecu(query: str, ecu_path=None) -> dict | None:
    """Fuzzy-match query against dataecu.json (supports both old and new V5 formats)."""
    ecu_path = ecu_path or ECU_PATH
    with open(ecu_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    # Handle New V5 structure (List under 'ecus') or Old structure (Dict of ECUs)
    if isinstance(data, dict) and "ecus" in data:
        ecu_db_list = data["ecus"]
    elif isinstance(data, dict):
        # Convert old dict structure to list for unified processing
        ecu_db_list = []
        for k, v in data.items():
            if k == "metadata": continue
            v["id"] = k
            ecu_db_list.append(v)
    else:
        ecu_db_list = data # Assume it's a list already

    q = query.lower().strip()

    # Pass 0: alias table
    for phrase, alias_key in _ALIASES.items():
        if phrase in q:
            for entry in ecu_db_list:
                if str(entry.get("id")).lower() == alias_key:
                    return entry

    # Pass 1: exact ID or name match
    for entry in ecu_db_list:
        eid = str(entry.get("id", "")).lower()
        ename = str(entry.get("name", eid)).lower()
        if eid == q or ename == q or f" {eid} " in f" {q} " or f" {ename} " in f" {q} ":
            return entry

    # Pass 2: acronym match
    qa = _acronym(q)
    if qa:
        for entry in ecu_db_list:
            eid = str(entry.get("id", "")).lower()
            if qa == eid:
                return entry

    # Pass 3: fuzzy name/id overlap
    for entry in ecu_db_list:
        eid = str(entry.get("id", "")).lower()
        ename = str(entry.get("name", eid)).lower()
        if eid in q or ename in q:
            return entry

    return None


def list_ecus(ecu_path=None) -> None:
    """Print all ECU keys and names from dataecu.json (V5)."""
    ecu_path = ecu_path or ECU_PATH
    with open(ecu_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    if isinstance(data, dict) and "ecus" in data:
        ecu_db_list = data["ecus"]
    elif isinstance(data, dict):
        ecu_db_list = [{"id": k, **v} for k, v in data.items() if k != "metadata"]
    else:
        ecu_db_list = data

    print(f"\n{'ID':<20} {'Name/Type'}")
    print("-" * 60)
    for entry in ecu_db_list:
        eid = entry.get("id", "??")
        ename = entry.get("name") or entry.get("type", "ECU")
        print(f"  {eid:<18} {ename}")
    print(f"\nTotal: {len(ecu_db_list)} ECU entries")


def build_enriched_query(user_query: str, ecu_entry: dict | None) -> str:
    if ecu_entry:
        name = ecu_entry.get("name") or ecu_entry.get("id", "Unknown ECU")
        
        # Build dynamic hints from structured V5 data
        hardware = ecu_entry.get("hardware", {})
        mcu = hardware.get("mcu", "Standard MCU")
        sensors = ", ".join(hardware.get("sensors", []))
        interfaces = ", ".join(hardware.get("interfaces", []))
        
        assets = []
        for a in ecu_entry.get("assets", []):
            if isinstance(a, dict):
                assets.append(f"{a.get('id')} ({a.get('type')})")
            else:
                assets.append(str(a))
        
        hint = ecu_entry.get("hint")
        if not hint:
            hint = f"Hardware: {mcu}. Interfaces: {interfaces}. Sensors: {sensors}. Assets: {', '.join(assets)}."

        return (
            f"Target System: {name}\n\n"
            f"AUTHORITATIVE ASSET LIST & HINTS: {hint}\n\n"
            f"All threat analysis and damage scenarios must reference the components above."
        )
    return user_query


# ─────────────────────────────────────────────────────────────────────────────
# POST-PROCESSING
# ─────────────────────────────────────────────────────────────────────────────

def _hex_id(base=None, inc=0):
    """Generates a 24-char hex ID. If base is provided, increments it."""
    if base and len(base) >= 24:
        # Simple hex increment for the last part
        prefix = base[:-2]
        val = int(base[-2:], 16) + inc
        return f"{prefix}{val:02x}"
    # Generate fresh 24-char hex
    return _uuid.uuid4().hex[:24]

def stamp_uuids(obj: dict) -> dict:
    """Replace placeholder IDs with industry-standard hex IDs and follow sequential logic."""
    
    # 1. Handle top-level entities with precise hex offsets
    models = obj.get("Models", [])
    assets = obj.get("Assets", [])
    attacks = obj.get("Attacks", [])
    ds_list = obj.get("Damage_scenarios", [])
    ts_list = obj.get("Threat_scenarios", [])
    
    mid = None
    uid = None

    if models and isinstance(models, list):
        model0 = models[0]
        if not model0.get("_id") or "uuid" in str(model0.get("_id")):
            model0["_id"] = _hex_id()
        if not model0.get("user_id") or "uuid" in str(model0.get("user_id")):
            model0["user_id"] = _hex_id()
            
        mid = model0["_id"]
        uid = model0["user_id"]
        
        # Apply offsets (Matching reference golden schema logic: Asset +1, Attack +2, DS +8, TS +11)
        # Note: offsets are approximate based on user's reference file
        for asset in assets:
            if not asset.get("_id") or "uuid" in str(asset.get("_id")):
                asset["_id"] = _hex_id(mid, 1)
            asset["model_id"] = mid
            asset["user_id"] = uid
            
        for attack in attacks:
            if not attack.get("_id") or "uuid" in str(attack.get("_id")):
                attack["_id"] = _hex_id(mid, 2)
            attack["model_id"] = mid

        for ds in ds_list:
            if not ds.get("_id") or "uuid" in str(ds.get("_id")):
                ds["_id"] = _hex_id(mid, 8)
            ds["model_id"] = mid
            if "user_id" not in ds: ds["user_id"] = uid

        for ts in ts_list:
            if not ts.get("_id") or "uuid" in str(ts.get("_id")):
                ts["_id"] = _hex_id(mid, 11)
            ts["model_id"] = mid

    # 2. General walk for internal IDs
    ID_KEYS = {"id", "_id", "parentId", "source", "target", "nodeId", "rowId", "propId", "threat_id", "ID"}
    
    def _bad(val):
        if not val: return True
        if isinstance(val, str) and ("PLACEHOLDER" in val or val.strip() == "" or val.startswith("<")):
            return True
        return False

    # For everything else, use standard UUID
    def _walk(o):
        if isinstance(o, dict):
            for k, v in list(o.items()):
                if k in ID_KEYS and _bad(v):
                    o[k] = str(_uuid.uuid4())
                else:
                    _walk(v)
        elif isinstance(o, list):
            for item in o:
                _walk(item)

    _walk(obj)
    return obj


def crosslink_node_ids(obj: dict) -> dict:
    """Links node labels to IDs across template and Details for all Assets."""
    assets_list = obj.get("Assets", [])
    if not isinstance(assets_list, list):
        return obj

    for asset in assets_list:
        template = asset.get("template", {})
        nodes = template.get("nodes", [])
        edges = template.get("edges", [])
        details = asset.get("Details", asset.get("details", []))
        
        # Build mapping for this asset
        label_to_id = {
            n.get("data", {}).get("label", "").lower(): n.get("id")
            for n in nodes if n.get("id")
        }

        # 1. Links in Edges
        for edge in edges:
            src_label = str(edge.get("source", "")).lower()
            tgt_label = str(edge.get("target", "")).lower()
            if src_label in label_to_id:
                edge["source"] = label_to_id[src_label]
            if tgt_label in label_to_id:
                edge["target"] = label_to_id[tgt_label]

        # 2. Links in Details
        if details:
            # Enforce capitalization
            asset["Details"] = details
            if "details" in asset: del asset["details"]
            
            for d in details:
                name_key = str(d.get("name", "")).lower()
                nid = d.get("nodeId", "")
                if not nid or str(nid).startswith("<") or "PLACEHOLDER" in str(nid):
                    d["nodeId"] = label_to_id.get(name_key) or str(_uuid.uuid4())
                
                # Assign IDs to properties if missing
                for p in d.get("props", []):
                    if not p.get("id") or str(p.get("id")).startswith("<"):
                        p["id"] = str(_uuid.uuid4())
    
    # 3. Links in Damage Scenarios
    global_label_to_id = {}
    prop_label_to_id = {} # node_label -> prop_name -> prop_uuid
    
    for asset in assets_list:
        for n in asset.get("templates", asset.get("template", {})).get("nodes", []):
            label = n.get("data", {}).get("label", "").lower()
            if label: global_label_to_id[label] = n.get("id")
        
        # Details props
        for det in asset.get("Details", []):
            n_label = det.get("name", "").lower()
            if n_label not in prop_label_to_id: prop_label_to_id[n_label] = {}
            for p in det.get("props", []):
                prop_label_to_id[n_label][p.get("name", "").lower()] = p.get("id")

    # Fix Damage Derivations
    ds_root_list = obj.get("Damage_scenarios", [])
    for ds_root in ds_root_list:
        for d in ds_root.get("Derivations", []):
            n_key = str(d.get("name", "")).split("for")[-1].strip().lower() # Fallback extraction
            if not d.get("nodeId") or str(d.get("nodeId")).startswith("<"):
                d["nodeId"] = global_label_to_id.get(n_key) or str(_uuid.uuid4())

    # Fix Threat Scenarios
    ts_root_list = obj.get("Threat_scenarios", [])
    for ts_root in ts_root_list:
        for ts_det in ts_root.get("Details", []):
            for inner in ts_det.get("Details", []):
                n_key = str(inner.get("node", "")).lower()
                if not inner.get("nodeId") or str(inner.get("nodeId")).startswith("<"):
                    inner["nodeId"] = global_label_to_id.get(n_key) or str(_uuid.uuid4())
                for p in inner.get("props", []):
                    p_name = str(p.get("name", "")).lower()
                    if n_key in prop_label_to_id and p_name in prop_label_to_id[n_key]:
                        p["id"] = prop_label_to_id[n_key][p_name]

    # Fix Attacks (Attack Trees)
    attacks_list = obj.get("Attacks", [])
    for attack in attacks_list:
        for scene in attack.get("scenes", []):
            for node in scene.get("templates", {}).get("nodes", []):
                # Link threat_ids
                for tid in node.get("threat_ids", []):
                    n_key = str(tid.get("node_name", "")).lower()
                    if n_key in global_label_to_id:
                        tid["nodeId"] = global_label_to_id[n_key]
                    
                    p_name = str(tid.get("prop_name", "")).lower()
                    if n_key in prop_label_to_id and p_name in prop_label_to_id[n_key]:
                        tid["propId"] = prop_label_to_id[n_key][p_name]
    return obj


def parse_and_fix(raw_text: str) -> dict | None:
    """Strip markdown fences, parse JSON, stamp UUIDs, crosslink nodeIds."""
    cleaned = re.sub(r"^```[a-z]*\n?", "", raw_text.strip(), flags=re.MULTILINE)
    cleaned = re.sub(r"```$", "", cleaned.strip())
    try:
        obj = json.loads(cleaned)
    except json.JSONDecodeError as e:
        print(f"⚠️  JSON parse error: {e}")
        print(f"Raw output (first 500 chars):\n{cleaned[:500]}")
        return None
    return crosslink_node_ids(stamp_uuids(obj))


def print_summary(tara_json: dict) -> None:
    models = tara_json.get("Models", [])
    assets = tara_json.get("Assets", [])
    ds_list = tara_json.get("Damage_scenarios", [])
    
    if not assets or not isinstance(assets, list): 
        print("   [Warning] No Assets found in TARA output.")
        return

    asset = assets[0]
    template = asset.get("template", {})
    nodes = template.get("nodes", [])
    edges = template.get("edges", [])
    details = asset.get("Details", [])
    
    ds_root = ds_list[0] if ds_list else {}

    print(f"   Nodes          : {len(nodes)}")
    print(f"   Edges          : {len(edges)}")
    print(f"   Architecture Details : {len(details)}")
    print(f"   Damage Scenarios : {len(ds_root.get('Details', []))}")
    print("   IDs            : stamped as compliant hex IDs")


# ─────────────────────────────────────────────────────────────────────────────
# HAYSTACK COMPONENT BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

def build_store(all_docs=None):
    """Embed all_docs, load into WeaviateDocumentStore. Skip if already populated."""
    store = WeaviateDocumentStore(
        url=WEAVIATE_URL,
        auth_client_secret=AuthApiKey(api_key=Secret.from_token(WEAVIATE_API_KEY)),
        collection_settings={"class": WEAVIATE_COLLECTION},
        additional_config=AdditionalConfig(timeout=Timeout(init=60, query=60, insert=60))
    )
    
    text_embedder = SentenceTransformersTextEmbedder(model=EMBED_MODEL)
    text_embedder.warm_up()

    # 🚀 OPTIMIZATION: Check if data already exists in Weaviate Cloud
    force_reingest = os.environ.get("FORCE_REINGEST", "false").lower() == "true"
    try:
        count = store.count_documents()
        if count > 0 and not force_reingest:
            print(f"✅ Weaviate Cloud is already populated with {count} documents.")
            print(f"⚡ Skipping re-ingestion to save time and API quota. (Set FORCE_REINGEST=true to override)")
            return store, text_embedder
        if force_reingest:
            print("🔄 FORCE_REINGEST=true detected. Updating knowledge base...")
    except Exception as e:
        print(f"⚠️  Could not check document count: {e}")


    if not all_docs:
        print("⚠️ No documents provided and Weaviate is empty. Processing stopped.")
        return store, text_embedder

    print(f"✅ Embedders ready  [{EMBED_MODEL}]")
    doc_embedder = SentenceTransformersDocumentEmbedder(model=EMBED_MODEL)
    doc_embedder.warm_up()

    print(f"🔄 Embedding {len(all_docs)} documents and storing in Weaviate...")
    embedded_docs = doc_embedder.run(documents=all_docs)["documents"]
    store.write_documents(embedded_docs, policy=DuplicatePolicy.OVERWRITE)
    print(f"✅ {store.count_documents()} documents embedded and stored in Weaviate.")
    return store, text_embedder



def build_retriever(store):
    return WeaviateEmbeddingRetriever(document_store=store, top_k=RETRIEVER_TOP_K)


def build_generator():
    if "GOOGLE_API_KEY" not in os.environ:
        raise EnvironmentError(
            "❌ GOOGLE_API_KEY not set.\n"
            "   Windows : set GOOGLE_API_KEY=your-key-here\n"
            "   Linux   : export GOOGLE_API_KEY=your-key-here"
        )
    return GoogleAIGeminiGenerator(model=GEMINI_MODEL)
    
def build_ranker():
    ranker = SentenceTransformersSimilarityRanker(model=RANKER_MODEL, top_k=TOP_K_RANKER)
    ranker.warm_up()
    return ranker
