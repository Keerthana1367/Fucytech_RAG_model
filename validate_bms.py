"""
Comprehensive BMS TARA Output Validator
Validates: node IDs, cross-references, edge integrity, threat-damage links,
and cross-checks against bms_1.json reference database.
"""
import json
import sys
import os
from collections import Counter, defaultdict

# Force UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

GENERATED = "outputs/Results/tara_output_BMS.json"
REFERENCE = "datasets/reports_db/bms_1.json"

def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def validate_output(data, label="OUTPUT"):
    issues = []
    warnings = []
    stats = {}

    # ── 1. TOP-LEVEL SCHEMA ──────────────────────────────────────────────────
    required_keys = ["Models", "Assets", "Damage_scenarios", "Threat_scenarios", "Attacks"]
    for k in required_keys:
        if k not in data:
            issues.append(f"[SCHEMA] Missing required top-level key: '{k}'")
    
    stats["top_level_keys"] = list(data.keys())

    # ── 2. NODE ID UNIQUENESS & HIERARCHY ────────────────────────────────────
    assets = data.get("Assets", [{}])
    asset = assets[0] if assets else {}
    nodes = asset.get("template", {}).get("nodes", [])
    edges = asset.get("template", {}).get("edges", [])
    details = asset.get("Details", [])

    node_ids = [n.get("id") for n in nodes]
    node_labels = {n.get("id"): n.get("data", {}).get("label", "?") for n in nodes}
    node_types = {n.get("id"): n.get("type", "?") for n in nodes}
    
    # Check uniqueness
    id_counts = Counter(node_ids)
    for nid, count in id_counts.items():
        if count > 1:
            issues.append(f"[NODE-ID] Duplicate node ID: '{nid}' appears {count} times")
    
    stats["node_count"] = len(nodes)
    stats["group_count"] = sum(1 for n in nodes if n.get("type") == "group")
    stats["component_count"] = sum(1 for n in nodes if n.get("type") != "group")

    # Check parentId references
    node_id_set = set(node_ids)
    for n in nodes:
        pid = n.get("parentId")
        if pid and pid not in node_id_set:
            issues.append(f"[PARENT-ID] Node '{node_labels.get(n['id'], n['id'])}' has parentId='{pid}' which does NOT exist in nodes")
        if pid is None and n.get("type") != "group":
            # Non-group at root level — might be external entity, just warn
            label = node_labels.get(n["id"], n["id"])
            if label not in ("Vehicle System", "Cloud"):
                warnings.append(f"[PARENT-ID] Non-group node '{label}' has parentId=null (should it be inside a group?)")

    # Top-level group should have parentId null
    groups = [n for n in nodes if n.get("type") == "group"]
    for g in groups:
        if g.get("parentId") is not None:
            pid = g["parentId"]
            if pid not in node_id_set:
                issues.append(f"[PARENT-ID] Group '{node_labels.get(g['id'])}' has parentId='{pid}' pointing to non-existent node")

    # ── 3. EDGE INTEGRITY ────────────────────────────────────────────────────
    edge_ids = [e.get("id") for e in edges]
    edge_id_counts = Counter(edge_ids)
    for eid, count in edge_id_counts.items():
        if count > 1:
            warnings.append(f"[EDGE-ID] Duplicate edge ID: '{eid}' appears {count} times")

    for e in edges:
        src = e.get("source")
        tgt = e.get("target")
        if src not in node_id_set:
            issues.append(f"[EDGE] Edge '{e.get('data', {}).get('label', '?')}' source='{src}' not in nodes")
        if tgt not in node_id_set:
            issues.append(f"[EDGE] Edge '{e.get('data', {}).get('label', '?')}' target='{tgt}' not in nodes")
        if src == tgt:
            warnings.append(f"[EDGE] Self-loop: edge source == target = '{src}'")

    stats["edge_count"] = len(edges)

    # ── 4. DETAILS <-> NODE CROSS-REFERENCE ────────────────────────────────────
    detail_node_ids = set()
    for d in details:
        dnid = d.get("nodeId")
        detail_node_ids.add(dnid)
        if dnid not in node_id_set:
            issues.append(f"[DETAIL] Detail '{d.get('name')}' references nodeId='{dnid}' which does NOT exist in nodes")
        # Check props have valid IDs
        for p in d.get("props", []):
            if not p.get("id"):
                warnings.append(f"[DETAIL] Prop '{p.get('name')}' on '{d.get('name')}' has empty/missing id")

    # Check all non-group nodes have a Detail entry
    for n in nodes:
        if n.get("type") != "group" and n["id"] not in detail_node_ids:
            warnings.append(f"[DETAIL] Node '{node_labels.get(n['id'])}' ({n['id']}) has no matching Detail entry")

    stats["detail_count"] = len(details)

    # -- 5. DAMAGE SCENARIOS --------------------------------------------------
    dmg = data.get("Damage_scenarios", [{}])
    dmg_entry = dmg[0] if dmg else {}
    derivations = dmg_entry.get("Derivations", [])
    dmg_details = dmg_entry.get("Details", [])

    stats["derivation_count"] = len(derivations)
    stats["damage_detail_count"] = len(dmg_details)

    # Validate derivation nodeIds
    for d in derivations:
        dnid = d.get("nodeId")
        if dnid not in node_id_set:
            issues.append(f"[DERIVATION] '{d.get('name', d.get('id'))}' nodeId='{dnid}' not in architecture nodes")

    # Validate damage detail cyberLosses nodeIds
    for d in dmg_details:
        for cl in d.get("cyberLosses", []):
            cnid = cl.get("nodeId")
            if cnid not in node_id_set:
                issues.append(f"[DAMAGE-DETAIL] '{d.get('Name')}' cyberLoss nodeId='{cnid}' not in architecture nodes")

    # Check derivation → damage detail pairing (by position)
    if len(derivations) != len(dmg_details):
        warnings.append(f"[DAMAGE] Derivation count ({len(derivations)}) != Detail count ({len(dmg_details)})")

    # Check impact values are valid
    valid_impacts = {"Negligible", "Minor", "Moderate", "Major", "Severe"}
    for d in dmg_details:
        for impact_key, val in d.get("impacts", {}).items():
            if val not in valid_impacts:
                issues.append(f"[DAMAGE-DETAIL] '{d.get('Name')}' has invalid impact '{impact_key}': '{val}'")

    # ── 6. THREAT SCENARIOS ──────────────────────────────────────────────────
    ts_list = data.get("Threat_scenarios", [{}])
    ts_entry = ts_list[0] if ts_list else {}
    ts_details = ts_entry.get("Details", [])
    
    stats["threat_scenario_count"] = len(ts_details)

    for ts in ts_details:
        ts_id = ts.get("id", "?")
        inner_details = ts.get("Details", [])
        if not inner_details:
            issues.append(f"[THREAT-SCENARIO] '{ts_id}' has empty Details array -- no threat entries")
        for inner in inner_details:
            # Check nodeId
            nid = inner.get("nodeId")
            if nid and nid not in node_id_set:
                issues.append(f"[THREAT-SCENARIO] '{ts_id}' -> '{inner.get('name', '?')}' nodeId='{nid}' not in architecture nodes")
            # Check props
            for p in inner.get("props", []):
                if not p.get("id"):
                    warnings.append(f"[THREAT-SCENARIO] Prop in '{inner.get('name', '?')}' has empty id")

    # ── 7. ATTACKS ───────────────────────────────────────────────────────────
    attacks = data.get("Attacks", [{}])
    atk_entry = attacks[0] if attacks else {}
    scenes = atk_entry.get("scenes", [])
    
    stats["attack_scene_count"] = len(scenes)

    for scene in scenes:
        scene_name = scene.get("Name", "?")
        atk_nodes = scene.get("templates", {}).get("nodes", [])
        for an in atk_nodes:
            for tid in an.get("threat_ids", []):
                # Check that threat_ids reference valid architecture nodeIds
                tnid = tid.get("nodeId")
                if tnid and tnid not in node_id_set:
                    issues.append(f"[ATTACK] Scene '{scene_name}' threat_id nodeId='{tnid}' not in architecture nodes")
                # Check damage_id links to a valid DS
                did = tid.get("damage_id", "")
                valid_ds_ids = {d.get("id") for d in ts_details}
                if did and did not in valid_ds_ids:
                    warnings.append(f"[ATTACK] Scene '{scene_name}' damage_id='{did}' not found in Threat_scenarios")

    return issues, warnings, stats


def cross_check(generated, reference):
    """Cross-check generated output against bms_1.json reference."""
    diffs = []
    
    # Compare top-level structure
    for key in ["Models", "Assets", "Damage_scenarios", "Threat_scenarios", "Attacks"]:
        if key in reference and key not in generated:
            diffs.append(f"[MISSING] Generated output missing '{key}' (present in reference)")
        elif key not in reference and key in generated:
            diffs.append(f"[EXTRA] Generated output has '{key}' not in reference")

    # Compare node counts
    ref_nodes = reference.get("Assets", [{}])[0].get("template", {}).get("nodes", [])
    gen_nodes = generated.get("Assets", [{}])[0].get("template", {}).get("nodes", [])
    
    ref_labels = sorted([n.get("data", {}).get("label", "?") for n in ref_nodes])
    gen_labels = sorted([n.get("data", {}).get("label", "?") for n in gen_nodes])
    
    diffs.append(f"[COMPARE] Reference: {len(ref_nodes)} nodes ({len([n for n in ref_nodes if n.get('type') == 'group'])} groups)")
    diffs.append(f"[COMPARE] Generated: {len(gen_nodes)} nodes ({len([n for n in gen_nodes if n.get('type') == 'group'])} groups)")
    
    # Label overlap
    ref_label_set = set(ref_labels)
    gen_label_set = set(gen_labels)
    
    only_in_ref = ref_label_set - gen_label_set
    only_in_gen = gen_label_set - ref_label_set
    common = ref_label_set & gen_label_set
    
    if only_in_ref:
        diffs.append(f"[REF-ONLY] Components only in reference: {only_in_ref}")
    if only_in_gen:
        diffs.append(f"[GEN-ONLY] Components only in generated: {only_in_gen}")
    if common:
        diffs.append(f"[MATCHED] Components in both: {common}")

    # Compare edge protocols
    ref_edges = reference.get("Assets", [{}])[0].get("template", {}).get("edges", [])
    gen_edges = generated.get("Assets", [{}])[0].get("template", {}).get("edges", [])
    ref_protocols = sorted(set(e.get("data", {}).get("label", "?") for e in ref_edges))
    gen_protocols = sorted(set(e.get("data", {}).get("label", "?") for e in gen_edges))
    diffs.append(f"[COMPARE] Reference edge protocols: {ref_protocols}")
    diffs.append(f"[COMPARE] Generated edge protocols: {gen_protocols}")
    
    # Compare damage scenario counts
    ref_dmg = reference.get("Damage_scenarios", [{}])[0].get("Details", [])
    gen_dmg = generated.get("Damage_scenarios", [{}])[0].get("Details", [])
    diffs.append(f"[COMPARE] Reference damage details: {len(ref_dmg)}, Generated: {len(gen_dmg)}")

    # Compare threat scenario counts
    ref_ts = reference.get("Threat_scenarios", [{}])[0].get("Details", [])
    gen_ts = generated.get("Threat_scenarios", [{}])[0].get("Details", [])
    diffs.append(f"[COMPARE] Reference threat scenarios: {len(ref_ts)}, Generated: {len(gen_ts)}")

    # Compare attack scene counts
    ref_atk = reference.get("Attacks", [{}])[0].get("scenes", [])
    gen_atk = generated.get("Attacks", [{}])[0].get("scenes", [])
    diffs.append(f"[COMPARE] Reference attack scenes: {len(ref_atk)}, Generated: {len(gen_atk)}")

    # Check reference node properties format
    ref_node_props = ref_nodes[0].get("properties", []) if ref_nodes else []
    gen_node_props = gen_nodes[0].get("properties", []) if gen_nodes else []
    ref_prop_type = type(ref_node_props[0]).__name__ if ref_node_props else "?"
    gen_prop_type = type(gen_node_props[0]).__name__ if gen_node_props else "?"
    if ref_prop_type != gen_prop_type:
        diffs.append(f"[FORMAT] Property format mismatch: ref uses {ref_prop_type}, gen uses {gen_prop_type}")

    return diffs


def main():
    print("=" * 70)
    print("  BMS TARA OUTPUT VALIDATOR")
    print("=" * 70)

    try:
        gen = load(GENERATED)
        print(f"\n  [Loaded] {GENERATED}")
    except FileNotFoundError:
        print(f"\n  [ERROR] File not found: {GENERATED}")
        sys.exit(1)

    issues, warnings, stats = validate_output(gen, "GENERATED")

    print(f"\n{'-' * 70}")
    print(f"  STATS")
    print(f"{'-' * 70}")
    for k, v in stats.items():
        print(f"    {k}: {v}")

    print(f"\n{'-' * 70}")
    print(f"  ISSUES ({len(issues)} critical)")
    print(f"{'-' * 70}")
    if issues:
        for i, issue in enumerate(issues, 1):
            print(f"  [!!] {i:2}. {issue}")
    else:
        print("  [OK] No critical issues found!")

    print(f"\n{'-' * 70}")
    print(f"  WARNINGS ({len(warnings)})")
    print(f"{'-' * 70}")
    if warnings:
        for i, w in enumerate(warnings, 1):
            print(f"  [??] {i:2}. {w}")
    else:
        print("  [OK] No warnings!")

    try:
        ref = load(REFERENCE)
        print(f"\n{'-' * 70}")
        print(f"  CROSS-CHECK vs {REFERENCE}")
        print(f"{'-' * 70}")
        diffs = cross_check(gen, ref)
        for d in diffs:
            print(f"    {d}")
    except FileNotFoundError:
        print(f"\n  [WARN] Reference file not found: {REFERENCE}")

    print(f"\n{'=' * 70}")
    status = "FAIL" if issues else "PASS (with warnings)" if warnings else "PASS"
    print(f"  RESULT: {status}")
    print(f"  Critical Issues: {len(issues)}  |  Warnings: {len(warnings)}")
    print(f"{'=' * 70}")

    return len(issues)


if __name__ == "__main__":
    sys.exit(main())
