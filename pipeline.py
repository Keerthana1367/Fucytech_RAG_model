from langgraph.graph import StateGraph
from typing import TypedDict
from collections import Counter
import jinja2
import os
import time
import json
import re
import copy
import uuid
from google.api_core.exceptions import ResourceExhausted
from cache_manager import save_cache, load_cache
import time
import uuid as _uuid

from components import build_store, build_retriever, build_generator, build_ranker
from config import RETRIEVER_TOP_K, TOP_K_RANKER
from prompt import TARA_PROMPT_TEMPLATE
import tenacity

# ── GLOBAL CONFIGURATION (Change these to adjust output depth) ───────────────
MAX_NODES       = 5    # Maximum architecture components to generate
MAX_THREATS     = 5    # Number of technical threat derivations (Agent 2)
MAX_SCENARIOS   = 5    # Number of STRIDE-mapped scenarios (Agent 3)

MIN_QUALITY_NODES = 3  # Minimum nodes required to pass quality check
MIN_QUALITY_TS    = 3  # Minimum scenarios required to pass quality check
# ─────────────────────────────────────────────────────────────────────────────

# ---------------- STATE ----------------
class RAGState(TypedDict):
    user_query: str
    enriched_query: str
    documents: list
    architecture: dict       # High-quality system design
    threats: list            # Detailed threat analysis
    damage_details: list     # Impact/damage details per threat
    threat_scenarios: list   # Automated Threat Scenarios
    attacks: list            # React Flow attack trees
    answer: str              # Final Combined JSON
    retry_count: int
    full_prompt: str
    eval_score: int
    eval_details: dict

# ---------------- SETUP ----------------
def setup(all_docs):
    store, text_embedder = build_store(all_docs)
    retriever = build_retriever(store)
    generator = build_generator()
    ranker = build_ranker()
    return retriever, generator, text_embedder, ranker

def safe_generate(prompt: str, role_name: str = "Agent"):
    """Thin wrapper to handle Gemini free-tier rate limits with auto-sleep and deep retries."""
    max_retries = 5  # Increased for better persistence
    for attempt in range(max_retries):
        try:
            return generator.run(parts=[prompt])
        except ResourceExhausted as e:
            # Deep back-off for free tier
            wait_time = 90 + (attempt * 60) 
            msg = str(e)
            if "retry in" in msg:
                try:
                    match = re.search(r"retry in ([\d.]+)", msg)
                    if match:
                        wait_time = int(float(match.group(1))) + 5
                except:
                    pass
            
            print(f"  ⚠️  {role_name} Quota hit (Attempt {attempt+1}/{max_retries}). Sleeping {wait_time}s...")
            time.sleep(wait_time)
        except Exception as e:
            print(f"  ❌ {role_name} error: {e}")
            time.sleep(10) # Small cooldown on generic errors
    return {"replies": ["Failed due to repeated quota errors."]}

def log_prompt(node_name: str, context: list, prompt: str, response: str):
    """Logs everything goig from RAG to LLM in outputs/prompts"""
    log_dir = os.path.join("outputs", "prompts")
    os.makedirs(log_dir, exist_ok=True)
    
    timestamp = str(int(time.time()))
    filename = f"{timestamp}_{node_name}.txt"
    filepath = os.path.join(log_dir, filename)
    
    with open(filepath, "w", encoding="utf-8") as f:
        log_content = f"=== {node_name.upper()} LOG ===\n"
        log_content += f"RAG CONTEXT (First 3 docs):\n"
        for i, doc in enumerate(context[:3]):
            content = getattr(doc, 'content', str(doc))
            log_content += f"DOC {i}: {content[:300]}...\n"
        log_content += "\n--- PROMPT ---\n"
        log_content += prompt
        log_content += "\n\n--- AI RESPONSE ---\n"
        log_content += response
        log_content += "\n" + "="*50 + "\n"
        
        f.write(log_content)
    return log_content

# ---------------- QUALITY-AWARE RETRY ----------------

MIN_NODES       = MIN_QUALITY_NODES
MIN_THREATS     = MIN_QUALITY_TS
MIN_DETAILS     = MIN_QUALITY_TS
MIN_SCENARIOS   = MIN_QUALITY_TS


def _score_section(state: RAGState) -> dict:
    """Per-section quality flags."""
    arch  = state.get("architecture", {})
    all_nodes = arch.get("template", {}).get("nodes", arch.get("nodes", []))
    nodes = [n for n in all_nodes if n.get("type") != "group"]
    threats   = state.get("threats", [])
    details   = state.get("damage_details", [])
    scenarios = state.get("threat_scenarios", [])
    return {
        "arch_ok":      len(nodes)     >= MIN_NODES,
        "threats_ok":   len(threats)   >= MIN_THREATS,
        "details_ok":   len(details)   >= MIN_DETAILS,
        "scenarios_ok": len(scenarios) >= MIN_SCENARIOS,
        "node_count":      len(nodes),
        "threat_count":    len(threats),
        "detail_count":    len(details),
        "scenario_count":  len(scenarios),
    }


def _should_retry(state: RAGState) -> str:
    """Quality-aware conditional edge.
    
    Checks each section against minimum quality thresholds.
    If any section fails AND we have retries left → retry.
    On retry, only FAILING sections are cleared from cache,
    so passing sections are served from cache (no wasted tokens).
    """
    retry     = state.get("retry_count", 0)
    max_retry = 2   # up to 2 reflection passes
    qc        = _score_section(state)

    failing = [k for k, v in qc.items() if k.endswith("_ok") and not v]

    print(f"  🔍 Quality Check | nodes={qc['node_count']} threats={qc['threat_count']} "
          f"details={qc['detail_count']} scenarios={qc['scenario_count']}")

    if failing and retry < max_retry:
        print(f"  🔁 Sections below threshold: {failing} — "
              f"retrying (attempt {retry+1}/{max_retry}) [cached sections preserved]")
        return "retry"
    elif failing:
        print(f"  ⚠️  Max retries reached. Accepting output (failing: {failing}).")
        return "done"
    else:
        print(f"  ✅ All sections passed quality check!")
        return "done"


def _bump_retry(state: RAGState):
    """Selectively clear ONLY failing sections from cache.
    
    Passing sections stay cached → their nodes return instantly from cache.
    Failing sections are evicted → their nodes will call the API again.
    """
    from cache_manager import get_cache_key
    query  = state.get("user_query", "")
    retry  = state.get("retry_count", 0) + 1
    qc     = _score_section(state)

    # Map section name to: (cache_step_key, state_key_to_clear)
    section_map = {
        "arch_ok":      ("architect",  "architecture"),
        "threats_ok":   ("threats",    "threats"),
        "details_ok":   ("damage",     "damage_details"),
        "scenarios_ok": (None,         "threat_scenarios"),  # deterministic, no cache key
    }

    reset_state = {"retry_count": retry}

    for flag, (cache_step, state_key) in section_map.items():
        if not qc.get(flag, True):   # section FAILED quality check
            print(f"  🗑️  Evicting cache for failing section: {state_key}")
            if cache_step:
                cache_file = get_cache_key(query, cache_step)
                if os.path.exists(cache_file):
                    os.remove(cache_file)
            reset_state[state_key] = [] if state_key != "architecture" else {}
        else:
            print(f"  💾 Keeping cache for passing section: {state_key}")

    return reset_state

@tenacity.retry(
    stop=tenacity.stop_after_attempt(3),
    wait=tenacity.wait_exponential(multiplier=1, min=4, max=10),
    retry=tenacity.retry_if_exception_type((Exception)),
    before_sleep=lambda retry_state: print(f"  ⚠️  Connection failed, retrying in {retry_state.next_action.sleep}s... (Attempt {retry_state.attempt_number})")
)
def retrieve(state: RAGState):
    """Retrieves relevant documents and re-ranks them for precision."""
    query = state.get("enriched_query") or state.get("user_query")
    print(f"  🔍 Retrieving top {RETRIEVER_TOP_K} candidate chunks...")
    try:
        embedding = text_embedder.run(text=query)["embedding"]
        result = retriever.run(query_embedding=embedding)
        raw_docs = result["documents"][:RETRIEVER_TOP_K]
        
        print(f"  🎯 Re-ranking to the best {TOP_K_RANKER} matches...")
        rank_res = ranker.run(query=query, documents=raw_docs)
        docs = rank_res["documents"]
        
        return {"documents": docs}
    except Exception as e:
        print(f"  ❌ Retrieval failed: {e}")
        raise e

def architect_node(state: RAGState):
    """Deep technical discovery to build the system architecture."""
    query = state.get("user_query", "") or state.get("query", "")
    
    # Check cache first
    cached = load_cache(query, "architect")
    if cached: return {"architecture": cached}
    
    # Bootstrap from existing results folder
    res_dir = os.path.join("outputs", "Results")
    # Try multiple filename variations
    variations = [
        f"tara_output_{query.replace(' ', '_')}.json",
        f"tara_output_{query}.json",
    ]
    
    # Temporarily bypass bootstrap to force LLM generation
    # for filename in variations:
    #     res_path = os.path.join(res_dir, filename)
    #     if os.path.exists(res_path):
    #         with open(res_path, "r") as f:
    #             data = json.load(f)
    #             arch = data.get("Assets", data.get("item_definition", {}))
    #             if arch: 
    #                 print(f"Bootstrapped Architect result from {filename}!")
    #                 save_cache(query, "architect", arch)
    #                 return {"architecture": arch}

    from prompt import ARCHITECT_PROMPT
    print(f"Architecting system (Target: {MAX_NODES} nodes)...")
    
    tmpl = jinja2.Template(ARCHITECT_PROMPT)
    prompt = tmpl.render(
        question=state["user_query"], 
        documents=state["documents"],
        max_nodes=MAX_NODES
    ) 
    
    result = safe_generate(prompt, "Architect")
    raw_json = result["replies"][0] if result["replies"] else "{}"
    
    # Log the RAG and LLM activity
    log_entry = log_prompt("architect_node", state["documents"], prompt, raw_json)
    
    # Cooldown
    time.sleep(10)
    try:
        cleaned = re.sub(r"^```[a-z]*\n?", "", raw_json.strip(), flags=re.MULTILINE)
        cleaned = re.sub(r"```$", "", cleaned.strip())
        arch_data = json.loads(cleaned)
        
        # Flexibly find architecture data (handles dict, list, or nested wrappers)
        if "template" in arch_data:
            assets = arch_data
        elif "Assets" in arch_data:
            a = arch_data["Assets"]
            assets = a[0] if isinstance(a, list) and a else a
        elif "assets" in arch_data:
            a = arch_data["assets"]
            assets = a[0] if isinstance(a, list) and a else a
        else:
            assets = arch_data
        
        # Validate node count
        nodes = assets.get("template", {}).get("nodes", assets.get("nodes", []))
        if not nodes:
            print(f" Architect FAIL: No nodes found in reply. Snippet: {raw_json[:150]}")
        else:
            print(f"Architect SUCCESS: Found {len(nodes)} nodes.")
            save_cache(query, "architect", assets)
        full_p = state.get("full_prompt", "") + "\n\n" + log_entry
        return {"architecture": assets, "full_prompt": full_p}
    except Exception as e:
        print(f"Architect parsing failed: {e}. Raw: {raw_json[:200]}")
        full_p = state.get("full_prompt", "") + "\n\n" + log_entry
        return {"architecture": {}, "full_prompt": full_p}

def threat_analysis_node(state: RAGState):
    """Deep technical threat discovery."""
    query = state.get("user_query", "") or state.get("query", "")
    
    # Check cache first
    cached = load_cache(query, "threats")
    if cached: return {"threats": cached}
    
    # Bootstrap check - scan results folder for any matching file
    # res_dir = os.path.join("outputs", "Results")
    # if os.path.exists(res_dir):
    #     for filename in os.listdir(res_dir):
    #         if query.lower().replace(" ", "") in filename.lower().replace(" ", ""):
    #             res_path = os.path.join(res_dir, filename)
    #             with open(res_path, "r") as f:
    #                 data = json.load(f)
    #                 threats = data.get("threat_scenarios", []) or data.get("damage_scenarios", {}).get("Derivations", [])
    #                 if threats: 
    #                     print(f"  ⚡ Bootstrapped Threat result from {filename}!")
    #                     save_cache(query, "threats", threats)
    #                     return {"threats": threats}

    from prompt import THREAT_PROMPT
    if not state.get("architecture"): return {"threats": []}
    
    print(f" Analyzing threats (Target: {MAX_THREATS} derivations)...")
    tmpl = jinja2.Template(THREAT_PROMPT)
    prompt = tmpl.render(
        question=state["user_query"],
        architecture=json.dumps(state["architecture"], indent=2),
        documents=state["documents"],
        max_threats=MAX_THREATS
    )
    
    result = safe_generate(prompt, "ThreatAnalyst")
    raw_json = result["replies"][0] if result["replies"] else "{}"
    
    # Log the RAG and LLM activity
    log_entry = log_prompt("threat_analysis_node", state["documents"], prompt, raw_json)
    full_p = state.get("full_prompt", "") + "\n\n" + log_entry
    
    try:
        cleaned = re.sub(r"^```[a-z]*\n?", "", raw_json.strip(), flags=re.MULTILINE)
        cleaned = re.sub(r"```$", "", cleaned.strip())
        threat_data = json.loads(cleaned)
        
        # Flexibly find threats
        threats = threat_data.get("Derivations", threat_data.get("threats", threat_data.get("derivations", [])))
        if not threats and isinstance(threat_data, list):
            threats = threat_data
            
        if not threats:
            print(f"Threat Analyst FAIL: 0 threats. Snippet: {raw_json[:150]}")
        else:
            print(f"Threat Analyst SUCCESS: Found {len(threats)} threats.")
            
        return {"threats": threats, "full_prompt": full_p}
    except Exception as e:
        print(f"Threat parsing failed: {e}. Raw: {raw_json[:200]}")
        return {"threats": [], "full_prompt": full_p}

def damage_scenario_node(state: RAGState):
    """AGENT 3: Focuses on Impact Ratings and Damage Scenarios."""
    from prompt import DAMAGE_PROMPT
    query = state.get("user_query", "") or state.get("query", "")

    # Check cache first
    cached = load_cache(query, "damage")
    if cached:
        return {"damage_details": cached}

    # Bootstrap from existing results file
    # res_dir = os.path.join("outputs", "Results")
    # if os.path.exists(res_dir):
    #     for filename in os.listdir(res_dir):
    #         if query.lower().replace(" ", "") in filename.lower().replace(" ", ""):
    #             res_path = os.path.join(res_dir, filename)
    #             with open(res_path, "r") as f:
    #                 data = json.load(f)
    #                 details = data.get("damage_scenarios", {}).get("Details", [])
    #                 if details:
    #                     print(f"Bootstrapped Damage result from {filename}!")
    #                     save_cache(query, "damage", details)
    #                     return {"damage_details": details}

    if not state.get("threats"): return {"damage_details": []}
    
    print("Assessing damage scenarios...")
    tmpl = jinja2.Template(DAMAGE_PROMPT)
    prompt = tmpl.render(
        threats=json.dumps(state["threats"], indent=2),
        architecture=json.dumps(state["architecture"], indent=2)
    )
    
    result = safe_generate(prompt, "DamageAnalyst")
    raw_json = result["replies"][0] if result["replies"] else "{}"
    
    # Log the RAG and LLM activity
    log_entry = log_prompt("damage_scenario_node", state.get("documents", []), prompt, raw_json)
    full_p = state.get("full_prompt", "") + "\n\n" + log_entry
    
    try:
        cleaned = re.sub(r"^```[a-z]*\n?", "", raw_json.strip(), flags=re.MULTILINE)
        cleaned = re.sub(r"```$", "", cleaned.strip())
        damage_data = json.loads(cleaned)
        
        # Flexibly find Details or full structure
        if "Damage_scenarios" in damage_data:
            details = damage_data["Damage_scenarios"]
        else:
            details = damage_data.get("Details", damage_data.get("details", damage_data.get("damage_details", [])))
            
        if not details and isinstance(damage_data, list):
            details = damage_data
            
        if not details:
            print(f"DEBUG: Raw Damage Response: {raw_json[:300]}")
            print(f" Damage Analyst FAIL: No scenarios found in JSON.")
        else:
            print(f"Damage Analyst SUCCESS: Found {len(details)} scenarios.")
            save_cache(query, "damage", details)
            
        return {"damage_details": details, "full_prompt": full_p}
    except Exception as e:
        print(f"DEBUG: Parsing error: {e}")
        print(f"DEBUG: Raw Damage Response: {raw_json[:500]}")
        return {"damage_details": [], "full_prompt": full_p}

def threat_scenario_agent_node(state: RAGState):
    """AGENT 4: Generates the dual Threat_scenarios structure using an LLM."""
    from prompt import THREAT_SCENARIO_PROMPT
    query = state.get("user_query", "") or state.get("query", "")

    if not state.get("damage_details"): return {"threat_scenarios": []}
    
    print("Generating context-aware Threat Scenarios (Agent 4)...")
    tmpl = jinja2.Template(THREAT_SCENARIO_PROMPT)
    prompt = tmpl.render(
        question=state["user_query"],
        architecture=json.dumps(state["architecture"], indent=2),
        damage_scenarios=json.dumps(state["damage_details"], indent=2),
        threats=json.dumps(state["threats"], indent=2)
    )
    
    result = safe_generate(prompt, "ThreatScenarioAnalyst")
    raw_json = result["replies"][0] if result["replies"] else "{}"
    
    # Log the RAG and LLM activity
    log_entry = log_prompt("threat_scenario_agent_node", state.get("documents", []), prompt, raw_json)
    full_p = state.get("full_prompt", "") + "\n\n" + log_entry
    
    try:
        cleaned = re.sub(r"^```[a-z]*\n?", "", raw_json.strip(), flags=re.MULTILINE)
        cleaned = re.sub(r"```$", "", cleaned.strip())
        ts_data = json.loads(cleaned)
        
        threat_scenarios = ts_data.get("Threat_scenarios", ts_data.get("threat_scenarios", []))
            
        if not threat_scenarios:
            print(f" Threat Scenario Agent FAIL: No scenarios found.")
        else:
            print(f"Threat Scenario Agent SUCCESS: Found {len(threat_scenarios)} scenario blocks.")
            
        return {"threat_scenarios": threat_scenarios, "full_prompt": full_p}
    except Exception as e:
        print(f"Threat Scenario parsing failed: {e}")
        return {"threat_scenarios": [], "full_prompt": full_p}

def generate_threat_scenarios_node_OLD(state: RAGState):
    """Generates the dual Threat_scenarios structure (derived + User-defined)."""
    print("Generating Threat Scenarios structure (derived + User-defined)...")
    
    damage_details = state.get("damage_details", [])
    
    def get_threat_type(value):
        mapping = {
            "Integrity": "Tampering",
            "Confidentiality": "Information Disclosure",
            "Availability": "Denial",
            "Authenticity": "Spoofing",
            "Authorization": "Elevation of Privilege",
            "Non-repudiation": "Rejection",
        }
        return mapping.get(value, "Security Violation")

    # 1. Flatten damage scenarios
    flat_ds = []
    if isinstance(damage_details, list):
        for block in damage_details:
            if not isinstance(block, dict): continue
            btype = block.get("type", "")
            if btype == "Derived":
                flat_ds.extend(block.get("Derivations", []))
            elif btype == "User-defined":
                flat_ds.extend(block.get("Details", []))
            else:
                flat_ds.append(block)

    derived_details = []
    user_defined_details = []
    
    # 2. Build 'derived' block
    for i, ds in enumerate(flat_ds):
        row_id = str(uuid.uuid4())
        ds_id = f"DS{i+1:03}"
        ds_name = ds.get("Name", ds.get("name", "Unnamed Scenario"))
        
        # Collect losses/nodes
        losses = ds.get("cyberLosses", ds.get("cyberlosses", []))
        if not losses:
            losses = [{"name": "Integrity", "node": "System", "nodeId": ds.get("nodeId", "unknown")}]

        # Group losses by nodeId for this Damage Scenario
        grouped_losses = {}
        for loss in losses:
            nid = loss.get("nodeId", "unknown")
            if nid not in grouped_losses:
                grouped_losses[nid] = {
                    "node": loss.get("node", "System"),
                    "nodeId": nid,
                    "props": []
                }
            
            loss_name = loss.get("name", "Integrity")
            prop_id = f"ts-{ds_id.lower()}-{grouped_losses[nid]['node'].lower().replace(' ', '-')[:10]}-{loss_name.lower()[:5]}"
            
            grouped_losses[nid]["props"].append({
                "id": prop_id,
                "is_risk_added": True if len(grouped_losses[nid]["props"]) == 0 else False,
                "name": loss_name,
                "isSelected": True,
                "key": len(grouped_losses[nid]["props"]) + 1
            })

        node_details = []
        for nid, node_info in grouped_losses.items():
            node_details.append({
                "node": node_info["node"],
                "nodeId": node_info["nodeId"],
                "props": node_info["props"],
                "name": ds_name
            })

        derived_details.append({
            "rowId": row_id,
            "id": ds_id,
            "Details": node_details
        })

    # 3. Build 'User-defined' block (Heuristic grouping)
    # Group threats by asset or theme to create a few realistic scenarios
    asset_groups = {}
    for entry in derived_details:
        for node in entry["Details"]:
            asset = node["node"]
            if asset not in asset_groups: asset_groups[asset] = []
            asset_groups[asset].append({
                "rowId": entry["rowId"],
                "nodeId": node["nodeId"],
                "propId": node["props"][0]["id"],
                "loss": node["props"][0]["name"]
            })

    for asset, members in asset_groups.items():
        main_loss = members[0]["loss"]
        threat_type = get_threat_type(main_loss)
        user_defined_details.append({
            "name": f"{threat_type} of {asset}",
            "description": f"Attack targeting the {asset} to compromise its {main_loss}. This could lead to system-wide impact.",
            "id": str(uuid.uuid4()),
            "threat_ids": [
                {
                    "propId": m["propId"],
                    "nodeId": m["nodeId"],
                    "rowId": m["rowId"]
                } for m in members
            ]
        })

    threat_scenarios = [
        {
            "_id": str(uuid.uuid4()),
            "model_id": "", # Filled during evaluate
            "type": "derived",
            "Details": derived_details,
            "user_id": "" # Filled during evaluate
        },
        {
            "_id": str(uuid.uuid4()),
            "model_id": "",
            "type": "User-defined",
            "Details": user_defined_details,
            "user_id": ""
        }
    ]
            
    return {"threat_scenarios": threat_scenarios}


def generate_attack_trees_node(state: RAGState):
    """Generates simplified attack trees for each threat scenario."""
    print("Generating Attack Trees (React Flow)...")
    ts_list = state.get("threat_scenarios", [])
    attacks = []
    
    def _create_node(label, name, x, y, desc="", node_type="default", threat_ids=None):
        uid = str(uuid.uuid4())
        return {
            "id": uid,
            "nodeId": uid,
            "type": "default",
            "nodeType": node_type,
            "label": label,
            "name": name,
            "description": desc,
            "dragged": True,
            "dragging": False,
            "selected": False,
            "height": 60,
            "width": 150,
            "position": {"x": x, "y": y},
            "positionAbsolute": {"x": x, "y": y},
            "data": {
                "label": label,
                "nodeId": uid,
                "nodeType": node_type,
                "connections": [{"id": str(uuid.uuid4()), "type": "OR Gate"}],
                "style": {
                    "backgroundColor": "transparent", "borderColor": "black", "borderStyle": "solid", "borderWidth": "2px",
                    "color": "black", "fontFamily": "Inter", "fontSize": "16px", "fontStyle": "normal", "fontWeight": 500,
                    "height": 60, "textAlign": "center", "textDecoration": "none", "width": 150
                }
            },
            "threat_ids": threat_ids or []
        }

    for ts in ts_list:
        nodes = []
        edges = []
        
        # Prepare threat_ids list
        # We need to find the rowId and other info from how Threat_scenarios was constructed
        # For now we use the info available in ts
        prop = ts.get("props", [{}])[0]
        t_ids = [
            {
                "damage_id": ts.get("damage_scenario", "").split("]")[0].strip("["),
                "damage_scene": ts.get("damage_scenario", "").split("]")[1].strip() if "]" in ts.get("damage_scenario", "") else "",
                "nodeId": ts.get("nodeId", ""),
                "node_name": ts.get("node", ""),
                "propId": prop.get("id", ""),
                "prop_key": prop.get("key", 1),
                "prop_name": prop.get("name", "Integrity"),
                "rowId": ts.get("rowId", "") # This will be injected during evaluate stage or we can pre-generate it
            }
        ]
        
        # Root Node
        name_only = ts.get("name", "Attack").split("]")[-1].strip()
        label = ts.get("name", "Attack")
        root = _create_node(label, name_only, 1184, -113, desc="Attack scenario description", node_type="derived", threat_ids=t_ids)
        nodes.append(root)
        
        attacks.append({
            "ID": str(uuid.uuid4()),
            "Name": name_only,
            "threat_id": "",
            "templates": {
                "nodes": nodes,
                "edges": edges
            }
        })
    
    return {"attacks": attacks}


def evaluate(state: RAGState):
    """Combine all agent outputs into the final TARA JSON and evaluate."""
    print("  📝 Combining and evaluating...")

    # Group threat scenarios by damage scenario ID (nodeIds remapped later)
    ts_list = state.get("threat_scenarios", [])
    # NOTE: threat_scenarios_details is built AFTER _remap() to get proper UUIDs

    # Assemble final JSON
    assets_data = state.get("architecture", {})
    assets_list = []
    
    if assets_data:
        if isinstance(assets_data, list): assets_list = assets_data
        else: assets_list = [assets_data]

    # ── Standard UUIDs for top-level entities ─────────────────────────────
    mid = str(uuid.uuid4()) 
    uid = str(uuid.uuid4()) 
    
    # 1. PRE-PROCESS: Ensure all assets have a 'template' key before mapping
    unified_assets = []
    for asset in assets_list:
        # If the asset is just a wrapper, unpack it
        if isinstance(asset, dict) and "Assets" in asset:
            sub = asset["Assets"]
            if isinstance(sub, list): unified_assets.extend(sub)
            else: unified_assets.append(sub)
        else:
            unified_assets.append(asset)
            
    for asset in unified_assets:
        # FORCE PACKING into 'template'
        if "template" not in asset or not asset["template"]:
            existing_nodes = asset.pop("nodes", [])
            existing_edges = asset.pop("edges", [])
            asset["template"] = {"nodes": existing_nodes, "edges": existing_edges}
        else:
            # Ensure nodes/edges are removed from root if they also exist in template
            asset.pop("nodes", None)
            asset.pop("edges", None)

    # 2. Standardize Node IDs and Create Deep Mapping
    node_id_map = {}
    label_id_map = {}
    for asset in unified_assets:
        nodes = asset["template"].get("nodes", [])
        for node in nodes:
            old_id = node.get("id")
            label = node.get("data", {}).get("label")
            new_uuid = str(uuid.uuid4())
            if old_id: node_id_map[old_id] = new_uuid
            if label:
                label_id_map[label] = new_uuid
                label_id_map[label.lower()] = new_uuid
            node["id"] = new_uuid
            node["nodeId"] = new_uuid
            if "data" in node: node["data"]["nodeId"] = new_uuid

    # 2b. Remap parentId references to new UUIDs
    for asset in unified_assets:
        for node in asset["template"].get("nodes", []):
            old_pid = node.get("parentId")
            if old_pid:
                node["parentId"] = node_id_map.get(
                    old_pid,
                    label_id_map.get(old_pid,
                    label_id_map.get(str(old_pid).lower(),
                    old_pid)))
            # If parentId maps to nothing valid and is not a UUID, set to null
            final_pid = node.get("parentId")
            if final_pid and final_pid not in [n.get("id") for n in asset["template"].get("nodes", [])]:
                node["parentId"] = None

    # 3. Final Styling and Metadata
    for asset in unified_assets:
        asset["_id"] = str(uuid.uuid4()) if "_id" not in asset else asset["_id"]
        asset["user_id"] = uid
        asset["model_id"] = mid
        asset["asset_name"] = asset.get("asset_name", None)
        asset["asset_properties"] = asset.get("asset_properties", None)
        
        # Clean: Move any nested 'details' to root
        nested_details = asset["template"].pop("details", asset["template"].pop("Details", []))
        if not asset.get("Details") and nested_details:
            asset["Details"] = nested_details
        # Nodes — always run
        nodes = asset["template"].get("nodes", [])
        # Collect group node IDs for child layout
        group_ids = {n.get("id") for n in nodes if n.get("type") == "group"}
        child_counters = {}  # Track child index per group for layout
        
        for i, node in enumerate(nodes):
            if "data" not in node: node["data"] = {}
            ntype = node.get("type", "default")
            
            # ── Determine correct dimensions per type (matches bms_1.json) ──
            if ntype == "group":
                default_w, default_h = 800, 500
            elif ntype == "data":
                default_w, default_h = 50, 30
            else:  # "default" components
                default_w, default_h = 150, 60
            
            # ── Layout logic ──
            pid = node.get("parentId")
            if "position" not in node:
                if ntype == "group":
                    node["position"] = {"x": -96.0, "y": -44.0}
                elif pid and pid in group_ids:
                    # Place children inside the group with offsets
                    ci = child_counters.get(pid, 0)
                    col = ci % 4
                    row = ci // 4
                    node["position"] = {"x": 20 + (col * 200), "y": 80 + (row * 150)}
                    child_counters[pid] = ci + 1
                else:
                    col = i % 3
                    node["position"] = {"x": 100 + (col * 350), "y": 100 + 300}
            
            node["positionAbsolute"] = node.get("positionAbsolute", node["position"])
            node["dragging"] = False
            node["resizing"] = False
            node["selected"] = False
            node["isAsset"] = node.get("isAsset", False)
            
            # zIndex: groups must be 0 so children render on top
            if ntype == "group":
                node["zIndex"] = 0
            
            # ── Properties: normalize to list of strings ──
            if "properties" not in node: 
                node["properties"] = ["Integrity"] # Minimal fallback
            else:
                clean_props = []
                for p in node["properties"]:
                    if isinstance(p, dict):
                        clean_props.append(p.get("name", p.get("value", "Integrity")))
                    else:
                        clean_props.append(str(p))
                node["properties"] = clean_props

            
            # ── Visual Styling (matches bms_1.json conventions) ──
            if "style" not in node["data"]:
                bg = "#dadada" if ntype == "group" else ("#e3e896" if ntype == "data" else "#FFFFFF")
                node["data"]["style"] = {
                    "backgroundColor": bg,
                    "borderColor": "gray",
                    "borderStyle": "solid",
                    "borderWidth": "2px",
                    "color": "black",
                    "fontFamily": "Inter",
                    "fontSize": "12px",
                    "fontStyle": "normal",
                    "fontWeight": 500,
                    "height": node.get("height", default_h),
                    "textAlign": "center",
                    "textDecoration": "none",
                    "width": node.get("width", default_w)
                }
            
            # Force correct dimensions (override any LLM-provided wrong sizes)
            node["data"]["style"]["height"] = node.get("height", default_h)
            node["data"]["style"]["width"] = node.get("width", default_w)
            node["height"] = node["data"]["style"]["height"]
            node["width"] = node["data"]["style"]["width"]
            node["style"] = {"height": node["height"], "width": node["width"]}
        
        # Edges — always run: remap source/target and enforce ReactFlow edge ID format
        edges = asset["template"].get("edges", [])
        for edge in edges:
            src = node_id_map.get(edge.get("source"), label_id_map.get(edge.get("source"), edge.get("source", "")))
            tgt = node_id_map.get(edge.get("target"), label_id_map.get(edge.get("target"), edge.get("target", "")))
            edge["source"] = src
            edge["target"] = tgt
            edge["sourceHandle"] = edge.get("sourceHandle", "b")
            edge["targetHandle"] = edge.get("targetHandle", "right")
            # ReactFlow standard edge ID format
            edge["id"] = f"reactflow__edge-{src}{edge['sourceHandle']}-{tgt}{edge['targetHandle']}"
            edge["type"] = "step"
            edge["animated"] = True
            edge["selected"] = False
            if "properties" not in edge: 
                edge["properties"] = ["Integrity"]
            else:
                clean_props = []
                for p in edge["properties"]:
                    if isinstance(p, dict):
                        clean_props.append(p.get("name", p.get("value", "Integrity")))
                    else:
                        clean_props.append(str(p))
                edge["properties"] = clean_props
            if "data" not in edge: edge["data"] = {}
            # Preserve edge label (e.g. "SPI_CellMonitor", "CAN2")
            if "label" not in edge["data"]:
                edge["data"]["label"] = edge.get("label", edge.get("name", "Connection"))
            edge["data"]["offset"] = 0
            edge["data"]["t"] = 0.5
            edge["markerEnd"] = {
                "color": "#64B5F6", "height": 18, "type": "arrowclosed", "width": 18
            }
            edge["markerStart"] = {
                "color": "#64B5F6", "height": 18, "orient": "auto-start-reverse", "type": "arrowclosed", "width": 18
            }
            edge["style"] = {
                "end": True, "start": True, "stroke": "#808080",
                "strokeDasharray": "0", "strokeWidth": 2
            }

        # Details handling: Remap nodeId and ensure prop formats
        if "Details" not in asset or not asset["Details"]:
            # Fallback Detail generation
            asset["Details"] = []
            for node in asset.get("template", {}).get("nodes", []):
                if node.get("type") != "group":
                    asset["Details"].append({
                        "nodeId": node.get("id"),
                        "name": node["data"].get("label", "Unknown"),
                        "desc": node["data"].get("description", "Auto-generated component"),
                        "type": node.get("type", "default"),
                        "props": [{"name": p, "id": str(uuid.uuid4())} for p in node.get("properties", ["Integrity"])]
                    })
        else:
            # Remap existing Details and fix any placeholder prop IDs
            for detail in asset["Details"]:
                detail["nodeId"] = node_id_map.get(
                    detail.get("nodeId"),
                    label_id_map.get(detail.get("nodeId"), detail.get("nodeId"))
                )
                
                # Standardize prop objects
                clean_props = []
                for prop in detail.get("props", []):
                    if isinstance(prop, str):
                        clean_props.append({"name": prop, "id": str(uuid.uuid4())})
                    else:
                        # Fix non-UUID IDs
                        pid = str(prop.get("id", ""))
                        if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', pid):
                            prop["id"] = str(uuid.uuid4())
                        clean_props.append(prop)
                detail["props"] = clean_props


    # ── DATA NORMALIZATION: Remap all state variables using the deep mapping ──
    def _remap(old_nid):
        if not old_nid: return old_nid
        return node_id_map.get(old_nid, label_id_map.get(old_nid, label_id_map.get(str(old_nid).lower(), old_nid)))

    # Process Threats (Raw)
    raw_threats = state.get("threats", [])
    raw_damage_details = state.get("damage_details", [])
    for i, t in enumerate(raw_threats):
        t["nodeId"] = _remap(t.get("nodeId"))
        if i < len(raw_damage_details):
             dd = raw_damage_details[i]
             if isinstance(dd, dict):
                 impacts = dd.get("impacts", {})
                 t["financial_impact"] = impacts.get("Financial Impact", "Severe")
                 t["safety_impact"] = impacts.get("Safety Impact", "Severe")
                 t["operational_impact"] = impacts.get("Operational Impact", "Severe")
                 t["privacy_impact"] = impacts.get("Privacy Impact", "Negligible")
                 if dd.get("Description"): t["description"] = dd["Description"]

    # Process Damage Details (Deep)
    if isinstance(raw_damage_details, list):
        for block in raw_damage_details:
            if not isinstance(block, dict): continue
            
            # Recurse into nested structures if found
            nested_items = []
            if block.get("type") == "Derived": nested_items = block.get("Derivations", [])
            elif block.get("type") == "User-defined": nested_items = block.get("Details", [])
            else: nested_items = [block]
            
            for item in nested_items:
                if not isinstance(item, dict): continue
                if "nodeId" in item: item["nodeId"] = _remap(item["nodeId"])
                for cl in item.get("cyberLosses", item.get("cyberlosses", [])):
                    cl["nodeId"] = _remap(cl.get("nodeId"))
                    if not cl.get("id") or not re.match(r'^[0-9a-f]{8}-', str(cl.get("id", ""))):
                        cl["id"] = str(uuid.uuid4())

    # Process Threat Scenarios (Automated)
    # ── EXTRACT Threat Scenarios for Assembly ──
    raw_ts_data = state.get("threat_scenarios", [])
    derived_ts_details = []
    user_defined_ts_details = []
    
    if isinstance(raw_ts_data, list):
        # The agent returns a list of blocks [ {type: "derived", Details: [...]}, {type: "User-defined", Details: [...]} ]
        for block in raw_ts_data:
            if not isinstance(block, dict): continue
            btype = block.get("type", "").lower()
            if btype == "derived":
                derived_ts_details = block.get("Details", [])
            elif btype == "user-defined":
                user_defined_ts_details = block.get("Details", [])
    
    # If the agent output was flat or failed, fall back to manual grouping logic for derived
    if not derived_ts_details and isinstance(raw_ts_data, list) and len(raw_ts_data) > 0:
        # Fallback: Treat raw_ts_data as a list of individual threat entries
        grouped_ts = {}
        for ts in raw_ts_data:
            if not isinstance(ts, dict): continue
            ds_ref = ts.get("damage_scenario", "")
            match = re.search(r"\[(DS\d+)\]", ds_ref)
            ds_id = match.group(1) if match else "Global"
            if ds_id not in grouped_ts: grouped_ts[ds_id] = []
            grouped_ts[ds_id].append(ts)
            
        for ds_id, ts_items in grouped_ts.items():
            node_grouping = {}
            ds_name = ""
            for ts in ts_items:
                nid = _remap(ts.get("nodeId", ""))
                if not ds_name: ds_name = ts.get("name", "Threat Scenario").split(']')[-1].strip()
                if nid not in node_grouping:
                    node_grouping[nid] = {"node": ts.get("node", "Component"), "nodeId": nid, "props": [], "name": ds_name}
                for p in ts.get("props", []):
                    node_grouping[nid]["props"].append({
                        "id": p.get("id", str(uuid.uuid4())),
                        "is_risk_added": p.get("is_risk_added", True),
                        "name": p.get("name", "Integrity"),
                        "isSelected": True,
                        "key": len(node_grouping[nid]["props"]) + 1
                    })
            derived_ts_details.append({
                "rowId": str(uuid.uuid4()),
                "id": ds_id,
                "Details": list(node_grouping.values())
            })
            
    threat_scenarios_details = derived_ts_details

    # ── BUILD Assets[0].Details: node + edge property list (matches bms_1.json) ──
    # This is the CRITICAL structure the frontend expects.
    # It includes BOTH nodes (type=default/data) and edges (type=step).
    first_asset = unified_assets[0] if unified_assets else {}
    if "Details" not in first_asset or not first_asset.get("Details"):
        asset_details = []
        # Add nodes (skip groups)
        for node in first_asset.get("template", {}).get("nodes", []):
            if node.get("type") == "group":
                continue
            asset_details.append({
                "nodeId": node.get("id"),
                "name": node.get("data", {}).get("label", "Unknown"),
                "desc": node.get("data", {}).get("description", None),
                "type": node.get("type", "default"),
                "props": [{"name": p, "id": str(uuid.uuid4())} for p in node.get("properties", [])]
            })
        # Add edges as Details entries (type=step, nodeId=edge id)
        for edge in first_asset.get("template", {}).get("edges", []):
            asset_details.append({
                "nodeId": edge.get("id", ""),
                "name": edge.get("data", {}).get("label", "Connection"),
                "desc": None,
                "type": "step",
                "props": [{"name": p, "id": str(uuid.uuid4())} for p in edge.get("properties", [])]
            })
        first_asset["Details"] = asset_details

    # ── EXTRACT Damage Scenarios ──
    raw_ds_data = state.get("damage_details", [])
    ds_derivations = []
    user_defined_ds_details = []
    
    if isinstance(raw_ds_data, list):
        for block in raw_ds_data:
            if not isinstance(block, dict): continue
            btype = block.get("type", "").lower()
            if btype == "derived":
                ds_derivations = block.get("Derivations", [])
            elif btype == "user-defined":
                user_defined_ds_details = block.get("Details", [])
            else:
                # Fallback for older agent format
                user_defined_ds_details.append(block)

    # ── CLEAN UP IDs for React Flow Compatibility ──
    for row in derived_ts_details:
        if "Details" in row:
            for item in row["Details"]:
                item["nodeId"] = _remap(item.get("nodeId"))
                for p in item.get("props", []):
                    if not re.match(r'^[0-9a-f]{8}-', str(p.get("id", ""))):
                        p["id"] = str(uuid.uuid4())

    # ── BUILD prop_id_map for consistency ──
    prop_id_map = {}
    for detail in first_asset.get("Details", []):
        nid = detail.get("nodeId")
        for p in detail.get("props", []):
            prop_id_map[(nid, p["name"])] = p["id"]

    for dd in user_defined_ds_details:
        # First remap nodeId in cyberLosses
        if "cyberLosses" in dd:
            for cl in dd["cyberLosses"]:
                cl["nodeId"] = _remap(cl.get("nodeId"))
                # Lookup consistent ID from prop_id_map
                mapped_id = prop_id_map.get((cl["nodeId"], cl.get("name")))
                if mapped_id:
                    cl["id"] = mapped_id
                elif not cl.get("id") or not re.match(r'^[0-9a-f]{8}-', str(cl.get("id", ""))):
                    cl["id"] = str(uuid.uuid4())
        
        # Clean the new nested Details array if any
        if "Details" in dd:
            for detail in dd["Details"]:
                detail["nodeId"] = _remap(detail.get("nodeId"))





    # ── BUILD Damage_scenarios.Derivations: one per prop per node/edge ──
    # This matches the golden ref: DS001="loss of Integrity for BatteryPack", etc.
    ds_derivations = []
    ds_counter = 1
    for detail in first_asset.get("Details", []):
        for prop in detail.get("props", []):
            ds_derivations.append({
                "id": f"DS{ds_counter:03}",
                "task": f"Check for DS due to the loss of {prop['name']} for {detail['name']}",
                "name": f"DS due to the loss of {prop['name']} for {detail['name']}",
                "loss": f"loss of {prop['name']}",
                "asset": False,
                "damageScene": [],
                "nodeId": detail.get("nodeId", ""),
                "is_checked": None
            })
            ds_counter += 1

    # ── BUILD final output matching bms_1.json golden schema ──
    # 1. Finalize Assets: ensure field ordering and presence of Details
    # (Requirement: _id, user_id, model_id must come BEFORE template)
    reordered_assets = []
    for asset in unified_assets:
        ordered = {
            "_id": asset.get("_id", str(uuid.uuid4())),
            "user_id": asset.get("user_id", uid),
            "model_id": asset.get("model_id", mid),
            "template": asset.get("template", {"nodes": [], "edges": []}),
            "Details": asset.get("Details", []),
            "asset_name": asset.get("asset_name", None),
            "asset_properties": asset.get("asset_properties", None)
        }
        reordered_assets.append(ordered)
    unified_assets = reordered_assets

    final_output = {
        "Models": [
            {
                "_id": mid,
                "user_id": uid,
                "name": state.get("user_query", "BatteryManagement"),
                "template": [],
                "created_by": "prabhu.desai@gmail.com",
                "Created_at": "2025-03-28T14:07:06.485Z",
                "last_updated": "2025-03-28T14:07:07Z",
                "status": 1
            }
        ],
        "Assets": unified_assets,
        "Attacks": [
            {
                "_id": str(uuid.uuid4()),
                "model_id": mid,
                "type": "attack_trees",
                "scenes": state.get("attacks", [])
            }
        ],
        "Damage_scenarios": [
            {
                "_id": str(uuid.uuid4()),
                "model_id": mid,
                "type": "Derived",
                "Derivations": ds_derivations,
                "Details": first_asset.get("Details", []),
                "user_id": uid
            },
            {
                "_id": str(uuid.uuid4()),
                "model_id": mid,
                "type": "User-defined",
                "Details": [
                    {
                        "Description": ds.get("Description", ds.get("description", "No description available.")),
                        "Name": ds.get("Name", ds.get("name", "Unnamed Scenario")),
                        "cyberLosses": ds.get("cyberLosses", ds.get("cyberlosses", [])),
                        "impacts": ds.get("impacts", {
                            "Financial Impact": "Moderate",
                            "Safety Impact": "Severe",
                            "Operational Impact": "Moderate",
                            "Privacy Impact": "Negligible"
                        }),
                        "key": i + 1,
                        "_id": ds.get("_id", ds.get("id", str(uuid.uuid4())))
                    } for i, ds in enumerate(user_defined_ds_details)
                ]
            }
        ],
        "Threat_scenarios": [
            {
                "_id": str(uuid.uuid4()),
                "model_id": mid,
                "type": "derived",
                "Details": derived_ts_details,
                "user_id": uid
            },
            {
                "_id": str(uuid.uuid4()),
                "model_id": mid,
                "type": "User-defined",
                "Details": user_defined_ts_details,
                "user_id": uid
            }
        ],
    }

    # (Details are now preserved in Assets as requested)

    # Post-processing to link rowId in Attacks
    try:
        threat_to_rowid = {}
        for block in final_output["Threat_scenarios"][0]["Details"]:
            for detail in block["Details"]:
                # Map by nodeId + property name to find rowId
                p_name = detail["props"][0]["name"] if detail["props"] else ""
                key = f"{detail['nodeId']}_{p_name}"
                threat_to_rowid[key] = block["rowId"]

        for scene in final_output["Attacks"][0]["scenes"]:
            for node in scene["templates"]["nodes"]:
                # Also remap the root nodeId of the attack node itself
                node["nodeId"] = node_id_map.get(node.get("nodeId"), label_id_map.get(node.get("nodeId"), node.get("nodeId")))
                if "data" in node:
                    node["data"]["nodeId"] = node_id_map.get(node["data"].get("nodeId"), label_id_map.get(node["data"].get("nodeId"), node["data"].get("nodeId")))

                for t_id_ref in node.get("threat_ids", []):
                    # REMAP: Ensure attack nodes point to the new UUIDs
                    t_id_ref["nodeId"] = node_id_map.get(t_id_ref.get("nodeId"), label_id_map.get(t_id_ref.get("nodeId"), t_id_ref.get("nodeId")))
                    
                    key = f"{t_id_ref['nodeId']}_{t_id_ref['prop_name']}"
                    if key in threat_to_rowid:
                        t_id_ref["rowId"] = threat_to_rowid[key]
    except Exception as e:
        print(f"  ⚠️  RowId linking skipped/failed: {e}")

    # ── FINAL UUID STAMPING (Integrated from backend postprocess) ──────────
    def _final_stamp(o):
        """Recursive walk to ensure all ID keys are valid UUIDs."""
        ID_KEYS = {"id", "_id", "model_id", "user_id", "nodeId", "rowId", "propId", "threat_id", "ID"}
        def _is_bad(val):
            if not val: return True
            if not isinstance(val, str): return False
            # If it's not a standard UUID (8-4-4-4-12) or contains placeholders
            is_uuid = re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', val.lower())
            return not is_uuid or "PLACEHOLDER" in val or "<" in val
            
        if isinstance(o, dict):
            for k, v in list(o.items()):
                if k in ID_KEYS and _is_bad(v):
                    o[k] = str(uuid.uuid4())
                else:
                    _final_stamp(v)
        elif isinstance(o, list):
            for item in o:
                _final_stamp(item)

    _final_stamp(final_output)

    answer = json.dumps(final_output, indent=2)

    # Quick scoring
    nodes = first_asset.get("template", {}).get("nodes", [])
    derivations = ds_derivations
    threats = ts_list

    score = 20
    if nodes:       score += 30
    if derivations: score += 25
    if threats:     score += 25

    retry = state.get("retry_count", 0)
    print(f"  EVALUATION: Multi-agent score {score}% (retry {retry})")
    
    # Detailed report
    eval_details = {
        "final_score": score,
        "retry_attempt": retry,
        "nodes_count": len(nodes),
        "derivations_count": len(derivations),
        "threat_scenarios_count": len(threat_scenarios_details),
        "item_definition_details_count": len(first_asset.get("Details", [])),
        "passed_quality_check": score >= 50
    }

    return {"eval_score": score, "eval_details": eval_details, "answer": answer}


# ---------------- BUILD GRAPH ----------------
def build_graph(all_docs):
    global retriever, generator, text_embedder, ranker
    retriever, generator, text_embedder, ranker = setup(all_docs)

    builder = StateGraph(RAGState)

    # Register all nodes
    builder.add_node("retrieve", retrieve)
    builder.add_node("architect", architect_node)
    builder.add_node("threats", threat_analysis_node)
    builder.add_node("damage", damage_scenario_node)
    builder.add_node("threat_scenarios", threat_scenario_agent_node)
    builder.add_node("attacks", generate_attack_trees_node)
    builder.add_node("evaluate", evaluate)

    # Clean linear graph
    builder.set_entry_point("retrieve")
    builder.add_edge("retrieve", "architect")
    builder.add_edge("architect", "threats")
    builder.add_edge("threats", "damage")
    builder.add_edge("damage", "threat_scenarios")
    builder.add_edge("threat_scenarios", "attacks")
    builder.add_edge("attacks", "evaluate")
    builder.add_edge("evaluate", "__end__")

    return builder.compile()