import json
import os
import argparse
import uuid
from pathlib import Path

# Try importing reportlab
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Frame, PageTemplate
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

def generate_markdown(tara_json, query):
    """Converts TARA JSON to a professional technical report in Markdown."""
    lines = []
    lines.append(f"# TARA Knowledge Document: {query}")
    lines.append(f"**Status**: Finalized Report")
    lines.append(f"**Generated**: {query}")
    lines.append("\n---\n")

    # 1. Assets / Architecture
    lines.append("## 1. System Architecture")
    assets_raw = tara_json.get("Assets", [{}])
    assets = assets_raw[0] if isinstance(assets_raw, list) and assets_raw else (assets_raw if isinstance(assets_raw, dict) else {})
    
    template = assets.get("template", {})
    nodes = template.get("nodes", [])
    details = template.get("details", [])
    details_map = {d.get("nodeId"): d for d in details}

    lines.append("| Component | Type | Description | Security Props |")
    lines.append("| :--- | :--- | :--- | :--- |")
    for node in nodes:
        node_id = node.get("id")
        data = node.get("data", {})
        label = data.get("label", node_id)
        label = node.get("data", {}).get("label", "Unknown")
        ntype = node.get("type", "default")
        detail = details_map.get(node_id, {})
        desc = detail.get("desc") or detail.get("Description") or "No description provided."
        # Support both 'props' and 'properties' keys
        raw_props = detail.get("props") or node.get("properties") or []
        props = [p.get("name") if isinstance(p, dict) else p for p in raw_props]
        props_str = ", ".join(props) if props else "None"
        lines.append(f"| {label} | {ntype} | {desc} | {props_str} |")
    lines.append("\n")

    # 2. Damage Scenarios
    lines.append("## 2. Damage Assessment")
    ds_root = tara_json.get("Damage_scenarios", [])
    # Find the User-defined block (not Derived)
    user_defined_ds = []
    if isinstance(ds_root, list):
        for block in ds_root:
            if block.get("type") == "User-defined":
                user_defined_ds = block.get("Details", [])
                break
    for ds in user_defined_ds:
        lines.append(f"#### {ds.get('Name')}")
        lines.append(f"- **Description**: {ds.get('Description')}")
        impacts = ds.get("impacts", {})
        impact_str = ", ".join([f"{k}: {v}" for k, v in impacts.items() if v])
        lines.append(f"- **Impact Ratings**: {impact_str}")
        losses = ds.get("cyberLosses", [])
        loss_list = [f"{l.get('name')} on {l.get('node')}" for l in losses]
        lines.append(f"- **Cyber Losses**: {', '.join(loss_list)}")
        lines.append("\n")

    # 3. Threat Scenarios
    lines.append("## 3. Threat Analysis & Attack Vectors")
    threats = extract_threat_scenarios(tara_json)
    for ts in threats:
        lines.append(f"#### TS: {ts.get('name', 'N/A')}")
        lines.append(f"- **ID**: {ts.get('short_id', ts.get('id', 'N/A'))}")
        lines.append(f"- **Category**: {ts.get('category', 'N/A')}")
        lines.append(f"- **Description**: {ts.get('description', 'N/A')}")
        lines.append(f"- **Asset at Risk**: {ts.get('asset', 'N/A')} ({ts.get('nodeId', 'N/A')})")
        lines.append(f"- **Cyber Loss**: {ts.get('cybersecurity_loss', 'N/A')}")
        tree = ts.get("attack_tree")
        if tree:
            lines.append("\n**Attack Tree Summary:**")
            lines.append(f"  - **Primary Goal**: {tree.get('goal')}")
            for vector in tree.get("children", []):
                lines.append(f"    - **Vector**: {vector.get('goal')}")
                for method in vector.get("children", []):
                    lines.append(f"      - **Method**: {method.get('goal')}")
        lines.append("\n")
    return "\n".join(lines)

def draw_background(canvas, doc):
    # Background is white by default, no need to draw a rectangle.
    # We just draw a subtle footer for professionalism.
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#666666"))
    canvas.drawCentredString(A4[0]/2, 0.4*inch, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()

def get_risk_level(impacts):
    impact_map = {"Severe": 4, "Major": 3, "Moderate": 2, "Minor": 1, "Negligible": 0}
    vals = [impact_map.get(v, 0) for v in impacts.values()]
    max_val = max(vals) if vals else 0
    if max_val >= 4: return "Critical"
    if max_val == 3: return "High"
    if max_val == 2: return "Medium"
    return "Low"

STRIDE_MAP = {
    "integrity": "Tampering",
    "confidentiality": "Information Disclosure",
    "availability": "Denial of Service",
    "authenticity": "Spoofing",
    "authorization": "Elevation of Privilege",
    "non-repudiation": "Repudiation"
}

def extract_threat_scenarios(tara_json):
    """Unified threat extraction to handle various JSON structures."""
    ts_root = tara_json.get("Threat_scenarios", [])
    if not ts_root:
        return []
        
    # Build maps for enrichment
    derived_prop_map = {}
    derived_row_map = {} # Using rowId as the most stable link
    
    for block in ts_root:
        if isinstance(block, dict) and block.get("type").lower() == "derived":
            for group in block.get("Details", []):
                ds_id = group.get("id")
                # Group rowId
                g_row_id = group.get("rowId")
                for detail in group.get("Details", []):
                    node_name = detail.get("node")
                    node_id = detail.get("nodeId")
                    # Threat detail rowId
                    row_id = detail.get("rowId") or g_row_id
                    attack_tree = detail.get("attack_tree")
                    
                    ref_data = {
                        "ds_id": ds_id,
                        "node": node_name,
                        "node_id": node_id,
                        "attack_tree": attack_tree,
                        "props": detail.get("props", [])
                    }
                    
                    if row_id:
                        derived_row_map[row_id] = ref_data
                    
                    for prop in detail.get("props", []):
                        prop_id = prop.get("id")
                        derived_prop_map[prop_id] = {
                            "ds_id": ds_id,
                            "row_id": row_id,
                            "node": node_name,
                            "node_id": node_id,
                            "prop_name": prop.get("name"),
                            "attack_tree": attack_tree
                        }
                        
    # Build attack tree map from global Attacks section (as secondary source)
    attack_map = {}
    attacks = tara_json.get("Attacks", [])
    if attacks and isinstance(attacks, list):
        for scene in attacks[0].get("scenes", []):
            t_id = scene.get("threat_id")
            if t_id:
                # Use 'tree' (hierarchical) or 'templates' (RF)
                attack_map[t_id] = scene.get("tree") or scene.get("templates")

    # Try User-defined first
    user_defined_details = []
    for block in ts_root:
        if isinstance(block, dict) and block.get("type") == "User-defined":
            user_defined_details = block.get("Details", [])
            break
            
    results = []
    if user_defined_details:
        for i, ts in enumerate(user_defined_details):
            enriched = ts.copy()
            # Assign sequential ID
            enriched["short_id"] = f"TS{i+1:03}"
            
            t_id = ts.get("id") or ts.get("_id")
            if t_id in attack_map:
                enriched["attack_tree"] = attack_map[t_id]
                
            t_ids = ts.get("threat_ids", [])
            if t_ids:
                # 1. Try rowId linking (Most reliable in ABS JSON)
                rid = t_ids[0].get("rowId")
                ref_from_row = derived_row_map.get(rid)
                
                if ref_from_row:
                    ref = {
                        "ds_id": ref_from_row["ds_id"],
                        "node": ref_from_row["node"],
                        "node_id": ref_from_row.get("node_id"),
                        "attack_tree": ref_from_row["attack_tree"],
                        "prop_name": ref_from_row["props"][0].get("name") if ref_from_row["props"] else "N/A"
                    }
                else:
                    # 2. Fallback to propId linking
                    ref = derived_prop_map.get(t_ids[0].get("propId"))
                
                if ref:
                    enriched["asset"] = enriched.get("asset") or ref["node"]
                    enriched["nodeId"] = enriched.get("nodeId") or ref.get("node_id")
                    enriched["cybersecurity_loss"] = enriched.get("cybersecurity_loss") or ref["prop_name"]
                    enriched["damage_scenario"] = enriched.get("damage_scenario") or ref["ds_id"]
                    enriched["attack_tree"] = enriched.get("attack_tree") or ref.get("attack_tree")
                    # Case-insensitive lookup for STRIDE
                    loss_key = ref["prop_name"].lower() if ref["prop_name"] else ""
                    enriched["category"] = enriched.get("category") or STRIDE_MAP.get(loss_key, "N/A")
            
            # Ensure no Nones
            enriched["asset"] = enriched.get("asset") or "N/A"
            enriched["cybersecurity_loss"] = enriched.get("cybersecurity_loss") or "N/A"
            enriched["category"] = enriched.get("category") or "N/A"
            
            results.append(enriched)
    else:
        # Fallback to derived
        for block in ts_root:
            if isinstance(block, dict) and block.get("type") == "derived":
                for group in block.get("Details", []):
                    ds_id = group.get("id")
                    for detail in group.get("Details", []):
                        for prop in detail.get("props", []):
                            prop_name = prop.get("name", "N/A")
                            results.append({
                                "short_id": f"TS{len(results)+1:03}",
                                "id": f"TS-{ds_id}-{prop.get('key', 1)}",
                                "name": detail.get("name", "Threat Scenario"),
                                "asset": detail.get("node"),
                                "nodeId": detail.get("nodeId"),
                                "cybersecurity_loss": prop_name,
                                "description": f"Potential loss of {prop_name} for {detail.get('node')}.",
                                "category": STRIDE_MAP.get(prop_name.lower(), "N/A"),
                                "damage_scenario": ds_id,
                                "attack_tree": detail.get("attack_tree") or attack_map.get(detail.get("nodeId"))
                            })
    return results

def generate_pdf(tara_json, query, output_path):
    """Converts TARA JSON to a premium dark-themed PDF report."""
    if not REPORTLAB_AVAILABLE:
        print("Error: ReportLab not installed. Cannot generate PDF.")
        return False

    doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=60, bottomMargin=50)
    styles = getSampleStyleSheet()
    
    # Premium Light Theme Styles
    black = colors.HexColor("#1a1a1a")
    dark_blue = colors.HexColor("#2e5a88")
    grey_text = colors.HexColor("#555555")
    border_color = colors.HexColor("#dddddd")
    
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=32, spaceAfter=10, textColor=dark_blue, leading=38)
    h1_style = ParagraphStyle('H1Style', parent=styles['Heading1'], fontSize=20, spaceBefore=20, spaceAfter=15, textColor=dark_blue, fontName="Helvetica-Bold")
    h2_style = ParagraphStyle('H2Style', parent=styles['Heading2'], fontSize=16, spaceBefore=15, spaceAfter=10, textColor=dark_blue, fontName="Helvetica-Bold")
    body_style = ParagraphStyle('BodyStyle', parent=styles['Normal'], fontSize=10, textColor=black, leading=14)
    table_text = ParagraphStyle('TableText', parent=styles['Normal'], fontSize=8, textColor=black, leading=10)
    table_header = ParagraphStyle('TableHeader', parent=styles['Normal'], fontSize=8, textColor=colors.white, fontName="Helvetica-Bold")
    
    story = []

    # --- COVER PAGE ---
    story.append(Spacer(1, 200))
    story.append(Paragraph("Threat Analysis & Risk Assessment Report", title_style))
    story.append(Spacer(1, 10))
    story.append(Paragraph(f"<font color='#5b9bd5' size='18'>ECU: {query}</font>", title_style))
    story.append(Spacer(1, 60))
    
    meta_data = [
        ["Standard:", "ISO/SAE 21434:2021"],
        ["Regulation:", "UNECE WP.29 R155 / R156"],
        ["Generated:", "2026-04-13T12:00:07+05:30"],
        ["Prepared by:", "FucyTech Automotive Cybersecurity"]
    ]
    for m in meta_data:
        story.append(Paragraph(f"<b>{m[0]}</b> {m[1]}", ParagraphStyle('Meta', parent=body_style, fontSize=11, textColor=grey_text)))
        story.append(Spacer(1, 4))
    
    story.append(PageBreak())

    # --- 1. ECU Description ---
    story.append(Paragraph("1. ECU Description", h1_style))
    ecu_desc_data = [
        [Paragraph("Field", table_header), Paragraph("Value", table_header)],
        ["ECU Name", query],
        ["ECU Type", "Automotive Controller"],
        ["Vehicle System", "High Voltage System" if "BMS" in query else "Chassis System"],
        ["Functions", "Critical control, monitoring and diagnostic services."],
        ["Interfaces", "CAN, Diagnostic (UDS)"],
        ["Environment", "Automotive In-Vehicle Network (IVN)"]
    ]
    t_ecu = Table(ecu_desc_data, colWidths=[150, 360])
    t_ecu.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), dark_blue),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('TEXTCOLOR', (0,0), (-1,-1), black),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_ecu)
    story.append(Spacer(1, 40))

    # --- 2. Executive Summary ---
    story.append(Paragraph("2. Executive Summary", h1_style))
    
    assets_raw = tara_json.get("Assets", [{}])
    assets = assets_raw[0] if isinstance(assets_raw, list) and assets_raw else (assets_raw if isinstance(assets_raw, dict) else {})
    nodes = assets.get("template", {}).get("nodes", [])
    
    # Extract User-defined damage scenario details (not Derived architecture nodes)
    ds_root = tara_json.get("Damage_scenarios", [])
    ds_details = []
    if isinstance(ds_root, list):
        for block in ds_root:
            if isinstance(block, dict) and block.get("type") == "User-defined":
                ds_details = block.get("Details", [])
                break
    
    ts_list = extract_threat_scenarios(tara_json)
    
    risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for ds in ds_details:
        lvl = get_risk_level(ds.get("impacts", {}))
        risk_counts[lvl] += 1
    
    summary_text = (
        f"This TARA identified {len(nodes)} cybersecurity assets, {len(ts_list)} threat scenarios, "
        f"and {len(ds_details)} distinct damage scenarios. "
        f"Risk assessment: <font color='red'>{risk_counts['Critical']} Critical</font>, "
        f"<font color='orange'>{risk_counts['High']} High</font>, "
        f"<font color='yellow'>{risk_counts['Medium']} Medium</font>, "
        f"{risk_counts['Low']} Low. "
        f"High-level security controls have been mapped for technical resolution."
    )
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 40))

    # --- 3. Asset Identification ---
    story.append(Paragraph("3. Asset Identification", h1_style))
    asset_data = [[Paragraph(h, table_header) for h in ["Asset Id", "Asset Name", "Asset Type", "Cybersecurity Props", "Description"]]]
    
    # Check both template.details and top-level Details for asset property info
    nodes_details = assets.get("template", {}).get("details", []) or assets.get("Details", [])
    # Also check Damage_scenarios Derived block for Details
    if not nodes_details and isinstance(ds_root, list):
        for block in ds_root:
            if isinstance(block, dict) and block.get("type") == "Derived":
                nodes_details = block.get("Details", [])
                break
    details_map = {d.get("nodeId"): d for d in nodes_details}
    
    for i, node in enumerate(nodes):
        node_id = node.get("id")
        detail = details_map.get(node_id, {})
        props = [p.get("name") if isinstance(p, dict) else p for p in detail.get("props", [])]
        asset_data.append([
            Paragraph(f"A{i+1}", table_text),
            Paragraph(node.get("data", {}).get("label", node_id), table_text),
            Paragraph(node.get("type", "default"), table_text),
            Paragraph(", ".join(props), table_text),
            Paragraph(detail.get("desc", "N/A"), table_text)
        ])
    
    t_asset = Table(asset_data, colWidths=[50, 100, 80, 100, 180])
    t_asset.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), dark_blue),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('TEXTCOLOR', (0,0), (-1,-1), black),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_asset)
    story.append(PageBreak())

    # --- 4. Damage Scenarios ---
    story.append(Paragraph("4. Damage Scenarios", h1_style))
    ds_headers = ["Dam id", "Asset Name", "Scenario Description", "Safety", "Financial", "Oper.", "Privacy", "Overall"]
    ds_table_data = [[Paragraph(h, table_header) for h in ds_headers]]
    
    for i, ds in enumerate(ds_details):
        impacts = ds.get("impacts", {})
        overall = get_risk_level(impacts)
        asset_name = ds.get("cyberLosses", [{}])[0].get("node", "System")
        
        row = [
            Paragraph(f"DS{i+1:03}", table_text),
            Paragraph(asset_name, table_text),
            Paragraph(ds.get("Description", "No desc"), table_text),
            Paragraph(impacts.get("Safety Impact", "N/A"), table_text),
            Paragraph(impacts.get("Financial Impact", "N/A"), table_text),
            Paragraph(impacts.get("Operational Impact", "N/A"), table_text),
            Paragraph(impacts.get("Privacy Impact", "N/A"), table_text),
            Paragraph(f"<b>{overall}</b>", table_text)
        ]
        ds_table_data.append(row)
        
    t_ds = Table(ds_table_data, colWidths=[40, 70, 170, 50, 50, 45, 45, 45])
    t_ds.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), dark_blue),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('TEXTCOLOR', (0,0), (-1,-1), black),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_ds)

    # --- 6. Threat Scenarios ---
    story.append(Paragraph("6. Threat Scenarios", h1_style))
    ts_headers = [Paragraph(h, table_header) for h in ["Threat Id", "Threat Name", "Targeted Asset", "Loss of Property", "Description", "Stride", "Vector"]]
    ts_table_data = [ts_headers]
    
    for ts in ts_list:
        vector = "Adjacent"
        tree = ts.get("attack_tree", {})
        
        # Check both hierarchical 'children' and React Flow 'nodes'
        if isinstance(tree, dict) and tree.get("children"):
            vector = tree["children"][0].get("goal", "Adjacent")
        elif isinstance(tree, dict) and tree.get("nodes"):
            # Fallback for React Flow structure
            for node in tree["nodes"]:
                if node.get("level") == 1 or "Vector" in node.get("data", {}).get("label", ""):
                    vector = node["data"]["label"]
                    break
        
        if len(vector) > 30: vector = vector[:27] + "..."
            
        ts_table_data.append([
            Paragraph(ts.get("short_id", "N/A"), table_text),
            Paragraph(ts.get("name", "N/A"), table_text),
            Paragraph(ts.get("asset", "N/A"), table_text),
            Paragraph(ts.get("cybersecurity_loss", "N/A"), table_text),
            Paragraph(ts.get("description", "N/A"), table_text),
            Paragraph(ts.get("category", "N/A"), table_text),
            Paragraph(vector, table_text)
        ])
        
    t_ts = Table(ts_table_data, colWidths=[45, 70, 70, 70, 130, 60, 65])
    t_ts.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), dark_blue),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('TEXTCOLOR', (0,0), (-1,-1), black),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_ts)
    story.append(PageBreak())

    # --- 7. Attack Path Analysis ---
    story.append(Paragraph("7. Attack Path Analysis", h1_style))
    
    # Logic to check if "Tools Required" should be shown
    has_tools = False
    ap_data_raw = []
    for i, ts in enumerate(ts_list):
        steps = []
        tree = ts.get("attack_tree", {})
        tools = []
        # Basic heuristic to extract tools from goal descriptions
        tool_keywords = ["JTAG", "SWD", "CANalyzer", "Busmaster", "Debugger", "Sniffer", "Glitching"]
        
        if isinstance(tree, dict) and tree.get("children"):
            for vector in tree.get("children", []):
                for method in vector.get("children", []):
                    goal = method.get("goal", "")
                    steps.append(goal)
                    for kw in tool_keywords:
                        if kw.lower() in goal.lower() and kw not in tools:
                            tools.append(kw)
        elif isinstance(tree, dict) and tree.get("nodes"):
            # Support for React Flow structure (flat list of nodes)
            for node in tree.get("nodes", []):
                label = node.get("data", {}).get("label", "")
                # Heuristic: deep nodes (methods) often have long descriptions
                if node.get("level") == 2 or len(label) > 30:
                    steps.append(label)
                    for kw in tool_keywords:
                        if kw.lower() in label.lower() and kw not in tools:
                            tools.append(kw)
        
        if tools: has_tools = True
        
        ap_data_raw.append({
            "path_id": f"AP{i+1:03}",
            "threat_id": ts.get("short_id", "N/A"),
            "feasibility": "Medium", # Default
            "tools": "; ".join(tools) if tools else "",
            "steps": " ".join([f"Step {j+1}: {s};" for j, s in enumerate(steps[:3])])
        })

    ap_headers = ["Path Id", "Threat Id", "Feasibility", "Attack Steps"]
    col_widths = [50, 60, 70, 330]
    if has_tools:
        ap_headers.insert(3, "Tools Required")
        col_widths = [45, 55, 60, 110, 240]
    
    ap_table_data = [[Paragraph(h, table_header) for h in ap_headers]]
    for ap in ap_data_raw:
        row = [
            Paragraph(ap["path_id"], table_text),
            Paragraph(ap["threat_id"], table_text),
            Paragraph(ap["feasibility"], table_text),
        ]
        if has_tools:
            row.append(Paragraph(ap["tools"] if ap["tools"] else "None", table_text))
        row.append(Paragraph(ap["steps"], table_text))
        ap_table_data.append(row)

    t_ap = Table(ap_table_data, colWidths=col_widths)
    t_ap.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), dark_blue),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('TEXTCOLOR', (0,0), (-1,-1), black),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_ap)
    story.append(Spacer(1, 40))

    # --- 8. Risk Rating ---
    story.append(Paragraph("8. Risk Rating", h1_style))
    risk_headers = [Paragraph(h, table_header) for h in ["Risk Id", "Threat Id", "Damage Id", "Risk Level", "Risk Value", "Risk Treatment"]]
    risk_table_data = [risk_headers]
    
    impact_num = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Negligible": 1}
    
    for i, ts in enumerate(ts_list):
        # Map back to damage scenario impact
        ds_id = "DS001"
        ts_asset = ts.get("asset", "N/A")
        ts_loss = ts.get("cybersecurity_loss", "N/A")
        ts_name = ts.get("name", "").lower()
            
        # Try to find which DS covers this property (Asset + Loss match)
        for j, ds in enumerate(ds_details):
            found = False
            # Factor 1: Cyber Loss Match (Asset + Loss)
            for loss in ds.get("cyberLosses", []):
                loss_node = loss.get("node", "")
                loss_name = loss.get("name", "")
                if (loss_node == ts_asset) and (loss_name == ts_loss):
                    ds_id = f"DS{j+1:03}"
                    found = True
                    break
            if found: break
            
            # Factor 2: Name Keyword Match (Fallback)
            ds_name = ds.get("Name", "").lower()
            if ds_name:
                # Check for significant keyword overlap
                keywords = ["firmware", "tampering", "injection", "spoof", "dos", "denial", "extraction", "key", "replay"]
                match_count = 0
                for kw in keywords:
                    if kw in ds_name and kw in ts_name:
                        match_count += 1
                if match_count >= 1:
                    ds_id = f"DS{j+1:03}"
                    break
        
        # Determine risk level correctly
        risk_level = "High"
        for ds in ds_details:
             if ds_id == f"DS{ds_details.index(ds)+1:03}":
                 risk_level = get_risk_level(ds.get("impacts", {}))
                 break
        
        risk_table_data.append([
            Paragraph(f"R{i+1:03}", table_text),
            Paragraph(ts.get("short_id", "N/A"), table_text),
            Paragraph(ds_id, table_text),
            Paragraph(risk_level, table_text),
            Paragraph(str(impact_num.get(risk_level, 3)), table_text),
            Paragraph("Reduce" if impact_num.get(risk_level, 3) >= 4 else "Accept", table_text)
        ])

    t_risk = Table(risk_table_data, colWidths=[60, 80, 80, 100, 80, 110])
    t_risk.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), dark_blue),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('TEXTCOLOR', (0,0), (-1,-1), black),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_risk)

    doc.build(story, onFirstPage=draw_background, onLaterPages=draw_background)
    return True

def main():
    parser = argparse.ArgumentParser(description="Export TARA JSON to MD and PDF.")
    parser.add_argument("--query", required=True, help="Query name")
    args = parser.parse_args()

    safe_name = args.query.replace(" ", "_")
    json_path = os.path.join("outputs", "Results", f"tara_output_{safe_name}.json")
    reports_db = os.path.join("datasets", "reports_db")
    pdf_reports_dir = os.path.join("outputs", "Reports")
    
    md_path = os.path.join(reports_db, f"knowledge_{safe_name}.md")
    pdf_path = os.path.join(pdf_reports_dir, f"TARA_Report_{safe_name}.pdf")

    if not os.path.exists(json_path):
        print(f"Error: {json_path} not found.")
        return

    with open(json_path, "r") as f:
        tara_json = json.load(f)

    # Generate MD for RAG
    print(f"Generating Markdown knowledge base...")
    os.makedirs(reports_db, exist_ok=True)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(generate_markdown(tara_json, args.query))

    # Generate PDF for User
    print(f"Generating Professional PDF report...")
    os.makedirs(pdf_reports_dir, exist_ok=True)
    if generate_pdf(tara_json, args.query, pdf_path):
        print(f"Success: PDF saved to: {pdf_path}")
    
    print(f"Done! Run 'python ingest.py' to update RAG.")

if __name__ == "__main__":
    main()
