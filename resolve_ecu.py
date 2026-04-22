# =============================================================================
# resolve_ecu.py — Fuzzy ECU matcher against dataecu.json
# =============================================================================

import json
from pathlib import Path

import config


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SUFFIX_WORDS = {
    "ecu", "system", "module", "interface", "controller", "unit",
    "network", "port", "server", "bus", "head", "vehicle", "automotive"
}

_ALIASES = {
    "obd":              "obd",
    "obd-ii":           "obd",
    "obd2":             "obd",
    "tcu":              "tcu",
    "telematics control": "tcu",
    "bcm":              "bcm",
    "ecm":              "ecm",
    "ivi":              "ivi",
    "eps":              "eps",
    "abs":              "abs",
    "bms":              "bms",
    "adas":             "adas",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _acronym(text: str) -> str:
    """Generate acronym, stripping generic automotive suffix words."""
    skip      = {"the", "and", "for", "of", "a", "an", "or", "in", "on", "to", "/"}
    words     = [w.strip("()/-").lower() for w in text.replace("/", " ").split()]
    sig_words = [w for w in words if w and w not in skip]
    core      = [w for w in sig_words if w not in _SUFFIX_WORDS]
    chosen    = core if core else sig_words
    return "".join(w[0] for w in chosen if w)


# ---------------------------------------------------------------------------
# Main resolver
# ---------------------------------------------------------------------------

def resolve_ecu(query: str, ecu_path=None) -> dict | None:
    """Fuzzy-match query against dataecu.json (supports both old and new V5 formats)."""
    ecu_path = ecu_path or config.ECU_PATH
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
    """Print all ECU keys and names from dataecu.json."""
    ecu_path = ecu_path or config.ECU_PATH
    with open(ecu_path, "r", encoding="utf-8") as f:
        ecu_db = json.load(f)
    print(f"\n{'Key':<20} {'Name'}")
    print("-" * 60)
    for key, entry in ecu_db.items():
        print(f"  {key:<18} {entry.get('name', '')}")
    print(f"\nTotal: {len(ecu_db)} ECU entries")
