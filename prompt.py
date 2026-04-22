# =============================================================================
# prompt.py — TARA generation prompt templates (Multi-Agent Pipeline)
# =============================================================================
#
# Each pipeline agent uses its own specialized prompt:
#   Architect Agent  → ARCHITECT_PROMPT  → System architecture (nodes, edges, Details)
#   Threat Analyst   → THREAT_PROMPT     → Threat derivations with nodeId refs
#   Damage Analyst   → DAMAGE_PROMPT     → Damage impact assessments
#
# TARA_PROMPT_TEMPLATE is retained for backward compatibility but is NOT
# called by any pipeline node. See the individual agent prompts below.
# =============================================================================


# ─────────────────────────────────────────────────────────────────────────────
# REFERENCE SCHEMA (imported by pipeline.py but NOT rendered by any node)
# ─────────────────────────────────────────────────────────────────────────────

TARA_PROMPT_TEMPLATE = """
[REFERENCE ONLY — This template is not used by any pipeline node.]

The final assembled TARA JSON structure (built by the evaluate() node from
individual agent outputs) follows this schema:

{
  "Models":            [{ "_id": "...", "name": "SystemName" }],
  "Assets":            [{ "template": { "nodes": [...], "edges": [...] }, "Details": [...] }],
  "Damage_scenarios":  [{ "Derivations": [...], "Details": [...] }],
  "Threat_scenarios":  [{ "Details": [{ "rowId": "...", "id": "DS001", "Details": [...] }] }],
  "Attacks":           [{ "type": "attack_trees", "scenes": [...] }]
}
"""


# ─────────────────────────────────────────────────────────────────────────────
# 1. ARCHITECT AGENT
# ─────────────────────────────────────────────────────────────────────────────

ARCHITECT_PROMPT = """
You are a Principal Automotive Systems Architect specializing in ISO 21434 TARA.

SYSTEM TO ARCHITECT: {{ question }}

### RETRIEVED CYBERSECURITY & REFERENCE CONTEXT:
{% for doc in documents %}
[{{ doc.meta.source }}]
{{ doc.content }}
---
{% endfor %}

### YOUR TASK:
Design a professional-grade system architecture for "{{ question }}" with exactly {{ max_nodes }} component nodes (excluding group containers).

### ARCHITECTURE RULES:

1. **HIERARCHY & REQUIRED COMPONENTS** — Use group containers and specific components:
   - For the target system, you must include ALL components and interfaces listed in the provided REFERENCE CONTEXT and ECU HINTS.
   - You MUST include relevant data nodes (e.g. `SoC`, `SoH` for battery systems, or `Speed`, `Angle` for control systems) as explicit components using `type: "data"`.
   - `type:"group"` nodes are invisible containers (dashed border, no solid backgroundColor).
   - The top-level system group has `"parentId": null`.
   - Sub-system groups nest inside the top-level group via `parentId`.
   - Component nodes (`type:"default"`) sit inside their parent group.
   - External entities (Vehicle System, Cloud) have `"parentId": null`.

2. **NODE IDs** — Use short, stable, lowercase, hyphenated strings:
   CORRECT: `"ecu-mcu-group"`, `"sensor-input"`, `"ext-interface"`
   WRONG:   UUIDs, bare numbers like "1", or labels with spaces.
   The pipeline will assign final UUIDs later — your IDs are for cross-referencing only.

3. **NODE TYPES**:
   - `"group"`: Invisible container. Style uses `background`, `border` (dashed). No `backgroundColor`.
   - `"default"`: Visible component. Style uses `backgroundColor` (solid color).
   - `"data"`: Small data items (SoC, SoH). Size: width=50, height=30.

4. **EDGES** — Short protocol labels ONLY:
   - You MUST include edges connecting the interfaces to their primary controller or data destination (e.g. `Sensor` -> `MCU`, `MCU` -> `Transceiver`).
   - You MUST include edges between internal groups and their respective components.
   - CORRECT: `"SPI"`, `"CAN1"`, `"CAN2"`, `"IO_PINS"`, `"Vehicle CAN"`, `"UART"`
   - WRONG:   `"Sends data to"`, `"Controls power"`, `"CAN Communication"`
   - Every `source` and `target` MUST match a defined node `id`.

5. **DETAILS** — For each non-group node, provide:
   - `nodeId`: MUST match the node's `id` exactly
   - `name`: MUST match the node's `data.label` exactly
   - `desc`: Technical description of the component
   - `type`: Same as the node's type ("default" or "data")
   - `props`: List of cybersecurity properties with unique IDs (e.g., `"p-cellmon-integ"`)

6. **COLOR CODING** by role:
   - Monitoring/sensing: yellow shades (`#e6df19`, `#accd32`)
   - I/O interfaces: beige/tan (`#e2dfc1`)
   - Flash/storage: purple (`#ccc8ea`)
   - Security (Keys, Certificates): green (`#51dc1e`, `#62c945`)
   - Debug ports: red/orange (`#e26a6a`)
   - Data items (SoC, SoH): light yellow (`#e3e896`)
   - External/generic: gray (`#dadada`)

7. **PROPERTIES** — Assign realistic subsets from:
   `Integrity`, `Confidentiality`, `Authenticity`, `Authorization`, `Availability`, `Non-repudiation`

8. **LAYOUT** — Assign non-overlapping positions:
   - Groups: large bounding boxes (e.g., 800×500 px)
   - Components: spread within groups (x: 100–900, y: 50–500)
   - No two nodes at the same position. No node at (0, 0).

### OUTPUT FORMAT:
Return ONLY a valid JSON object. No markdown fences. No commentary. Start with `{`.

{
  "template": {
    "nodes": [
      {
        "id": "sys-main-group",
        "type": "group",
        "parentId": null,
        "data": {
          "label": "System Name",
          "nodeCount": 5,
          "style": {
            "backgroundColor": "#dadada",
            "borderColor": "gray",
            "borderStyle": "solid",
            "borderWidth": "2px",
            "color": "black",
            "fontFamily": "Inter",
            "fontSize": "12px",
            "fontStyle": "normal",
            "fontWeight": 500,
            "height": 60,
            "textAlign": "center",
            "textDecoration": "none",
            "width": 150
          }
        },
        "position": {"x": 100, "y": 50},
        "positionAbsolute": {"x": 100, "y": 50},
        "height": 510,
        "width": 1041,
        "properties": ["Integrity", "Authenticity"],
        "style": {"height": 510, "width": 1041},
        "dragging": false,
        "resizing": false,
        "selected": false,
        "zIndex": 0
      },
      {
        "id": "comp-one",
        "type": "default",
        "parentId": "sys-main-group",
        "data": {
          "label": "ComponentName",
          "description": "Technical description of this component",
          "style": {
            "backgroundColor": "#dadada",
            "borderColor": "gray",
            "borderStyle": "solid",
            "borderWidth": "2px",
            "color": "black",
            "fontFamily": "Inter",
            "fontSize": "12px",
            "fontStyle": "normal",
            "fontWeight": 500,
            "height": 60,
            "textAlign": "center",
            "textDecoration": "none",
            "width": 150
          }
        },
        "position": {"x": 300, "y": 200},
        "positionAbsolute": {"x": 300, "y": 200},
        "height": 60,
        "width": 150,
        "isAsset": false,
        "properties": ["Integrity", "Confidentiality"],
        "style": {"height": 60, "width": 150},
        "dragging": false,
        "resizing": false,
        "selected": false,
        "zIndex": 0

      },
      {
        "id": "comp-two",
        "type": "default",
        "parentId": "sys-main-group",
        "data": {
          "label": "AnotherComponent",
          "description": "Description of second component",
          "style": {
            "backgroundColor": "#e6df19",
            "borderColor": "gray",
            "borderStyle": "solid",
            "borderWidth": "2px",
            "color": "black",
            "fontFamily": "Inter",
            "fontSize": "12px",
            "fontStyle": "normal",
            "fontWeight": 500,
            "height": 60,
            "textAlign": "center",
            "textDecoration": "none",
            "width": 150
          }
        },
        "position": {"x": 550, "y": 200},
        "positionAbsolute": {"x": 550, "y": 200},
        "height": 60,
        "width": 150,
        "isAsset": false,
        "properties": ["Integrity", "Availability"],
        "style": {"height": 60, "width": 150},
        "dragging": false,
        "resizing": false,
        "selected": false,
        "zIndex": 0
      }
    ],
    "edges": [
      {
        "id": "edge-comp1-comp2",
        "source": "comp-one",
        "target": "comp-two",
        "type": "step",
        "animated": true,
        "sourceHandle": "b",
        "targetHandle": "left",
        "properties": ["Integrity"],
        "data": {"label": "CAN", "offset": 0, "t": 0.5},
        "markerEnd": {"color": "#64B5F6", "height": 18, "type": "arrowclosed", "width": 18},
        "markerStart": {"color": "#64B5F6", "height": 18, "orient": "auto-start-reverse", "type": "arrowclosed", "width": 18},
        "style": {"end": true, "start": true, "stroke": "#808080", "strokeDasharray": "0", "strokeWidth": 2}
      }
    ]
  },
  "Details": [
    {
      "nodeId": "comp-one",
      "name": "ComponentName",
      "desc": "Technical description of this component",
      "type": "default",
      "props": [
        {
          "name": "Integrity",
          "id": "p-comp1-integ"
        },
        {
          "name": "Confidentiality",
          "id": "p-comp1-conf"
        }
      ]
    },
    {
      "nodeId": "comp-two",
      "name": "AnotherComponent",
      "desc": "Description of second component",
      "type": "default",
      "props": [
        {
          "name": "Integrity",
          "id": "p-comp2-integ"
        },
        {
          "name": "Availability",
          "id": "p-comp2-avail"
        }
      ]
    }
  ]
}
"""


# ─────────────────────────────────────────────────────────────────────────────
# 2. THREAT ANALYST AGENT
# ─────────────────────────────────────────────────────────────────────────────

THREAT_PROMPT = """
You are a Cybersecurity Threat Analyst performing ISO 21434 "Pin-Point Pinning" analysis.

TARGET SYSTEM: {{ question }}

### SYSTEM ARCHITECTURE:
{{ architecture }}

### RETRIEVED CYBERSECURITY CONTEXT:
{% for doc in documents %}
[{{ doc.meta.source }}]
{{ doc.content }}
---
{% endfor %}

### YOUR TASK:
Generate exactly {{ max_threats }} high-priority technical threats, each targeting a specific component node from the architecture above.

### THREAT DISCOVERY RULES:

1. **PIN TO NODE**: Each threat's `nodeId` MUST be the EXACT `id` value of a node from the architecture JSON above.
   Example: If a node has `"id": "sensor-input"`, use `"nodeId": "sensor-input"`.
   Do NOT use the label, a UUID, or any invented string.

2. **SPREAD**: Target DIFFERENT nodes. Do not cluster all threats on one component.

3. **DIVERSITY**: Include at least:
   - One PHYSICAL attack (Debug port, JTAG, hardware tampering)
   - One NETWORK attack (CAN bus injection, Ethernet replay, OTA exploit)
   - One SOFTWARE/DATA attack (Firmware corruption, calibration tampering, key extraction)

4. **LOSS TYPE**: Specify which cybersecurity property is lost using one of:
   `Integrity` | `Confidentiality` | `Authenticity` | `Authorization` | `Availability` | `Non-repudiation`

5. **REASONING**: Ground threats in real attack patterns from CWE, CAPEC, or MITRE ATT&CK when available from the context.

### OUTPUT FORMAT:
Return ONLY a valid JSON object. No markdown fences. No commentary. Start with `{`.

{
  "Derivations": [
    {
      "id": "T-01",
      "nodeId": "<exact-node-id-from-architecture>",
      "task": "Check for DS due to the loss of Integrity for ComponentName",
      "name": "Descriptive Threat Name",
      "loss": "Integrity",
      "asset": "Component Name",
      "damage_scene": "Detailed technical description of the attack and its consequences.",
      "isChecked": false
    },
    {
      "id": "T-02",
      "nodeId": "<different-node-id>",
      "task": "Check for DS due to the loss of Availability for OtherComponent",
      "name": "Another Threat Name",
      "loss": "Availability",
      "asset": "Other Component Name",
      "damage_scene": "Detailed technical scenario for this threat.",
      "isChecked": false
    }
  ]
}
"""


# ─────────────────────────────────────────────────────────────────────────────
# 3. DAMAGE ANALYST AGENT
# ─────────────────────────────────────────────────────────────────────────────

DAMAGE_PROMPT = """
You are a Damage Assessment Specialist performing ISO 21434 impact analysis.

### YOUR TASK:
For each threat below, generate a corresponding damage detail entry evaluating its impact.
You MUST generate exactly one Detail entry per threat — do NOT skip any.

### THREATS TO ASSESS:
{{ threats }}

### SYSTEM ARCHITECTURE (for node reference):
{{ architecture }}

### ASSESSMENT RULES:

1. **ONE-TO-ONE MAPPING**: Each threat gets exactly one Detail entry. Count of Details must equal count of threats.

2. **NODE REFERENCE**: The `nodeId` in `cyberLosses` MUST use the EXACT node `id` from the architecture.
   Copy the `nodeId` directly from the corresponding threat entry. Do NOT change it.

3. **CYBER LOSSES**: Map the threat's `loss` property to the correct node:
   - `name`: The cybersecurity property (e.g., "Integrity", "Availability")
   - `node`: The human-readable component name (from the threat's `asset` field)
   - `nodeId`: The exact node ID (from the threat's `nodeId` field)

4. **IMPACT RATING**: Assign ratings using ONLY these values:
   `Negligible` | `Minor` | `Moderate` | `Major` | `Severe`

### IMPACT GUIDELINES (ISO 21434 Annex F):
- **Safety**: Negligible=no injury | Minor=light injury | Moderate=severe injury | Major=life-threatening | Severe=fatal
- **Financial**: Negligible=<$100 | Minor=<$1K | Moderate=<$10K | Major=<$100K | Severe=>$100K
- **Operational**: Negligible=no disruption | Minor=minor delay | Moderate=reduced capability | Major=system unusable | Severe=fleet-wide
- **Privacy**: Negligible=no PII | Minor=anonymized | Moderate=limited PII | Major=sensitive PII | Severe=mass breach

### OUTPUT FORMAT:
Return ONLY a valid JSON object. No markdown fences. No commentary. Start with `{`.

{
  "Damage_scenarios": [
    {
      "_id": "698397514b57b8f24ed40a4b",
      "model_id": "698397514b57b8f24ed40a43",
      "type": "Derived",
      "Derivations": [
        {
          "id": "DS001",
          "nodeId": "<exact-node-id-from-architecture>",
          "is_checked": null
        }
      ],
      "Details": [
        {
          "nodeId": "<node-id-for-battery-pack>",
          "name": "BatteryPack",
          "desc": "Technical description",
          "type": "default",
          "props": [
            { "name": "Integrity", "id": "p-bp-integ" },
            { "name": "Confidentiality", "id": "p-bp-conf" },
            { "name": "Authenticity", "id": "p-bp-auth" },
            { "name": "Authorization", "id": "p-bp-author" },
            { "name": "Availability", "id": "p-bp-avail" },
            { "name": "Non-repudiation", "id": "p-bp-nonrep" }
          ]
        }
      ]
    },
    {
      "_id": "698397514b57b8f24ed40a4c",
      "model_id": "698397514b57b8f24ed40a43",
      "type": "User-defined",
      "Details": [
        {
          "Description": "Detailed scenario analysis...",
          "Name": "Short Scenario Name",
          "cyberLosses": [
            {
              "id": "cl-unique-id",
              "is_risk_added": true,
              "name": "Integrity",
              "isSelected": true,
              "node": "Code Flash",
              "nodeId": "<node-id-for-code-flash>"
            }
          ],
          "impacts": {
            "Financial Impact": "Severe",
            "Safety Impact": "Severe",
            "Operational Impact": "Severe",
            "Privacy Impact": "Negligible"
          },
          "key": 1,
          "_id": "dd-001"
        }
      ]
    }
  ]
}

"""
