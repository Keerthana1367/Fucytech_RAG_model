"""Quick smoke test: verify all prompts render correctly with mock data."""
import jinja2
from prompt import ARCHITECT_PROMPT, THREAT_PROMPT, DAMAGE_PROMPT

# Minimal mock document class
class MockDoc:
    def __init__(self, content, meta):
        self.content = content
        self.meta = meta

docs = [
    MockDoc("CWE-120: Buffer overflow in C/C++ code", {"source": "CWE"}),
    MockDoc("CAPEC-186: Malicious Software Update", {"source": "CAPEC"}),
    MockDoc("Reference Component [BMS]: CellMonitoring", {"source": "REPORTS_DB"}),
]

# Test 1: ARCHITECT_PROMPT
t1 = jinja2.Template(ARCHITECT_PROMPT)
r1 = t1.render(question="Battery Management System", documents=docs, max_nodes=5)
assert "CWE-120" in r1, "RAG docs not injected into ARCHITECT_PROMPT!"
assert "Battery Management System" in r1
print(f"[PASS] ARCHITECT_PROMPT: {len(r1)} chars, RAG docs injected OK")

# Test 2: THREAT_PROMPT  
t2 = jinja2.Template(THREAT_PROMPT)
r2 = t2.render(
    question="Battery Management System",
    architecture='{"template": {"nodes": [{"id": "bms-cell", "data": {"label": "CellMonitoring"}}]}}',
    documents=docs,
    max_threats=5
)
assert "CWE-120" in r2, "RAG docs not injected into THREAT_PROMPT!"
assert "bms-cell" in r2
print(f"[PASS] THREAT_PROMPT: {len(r2)} chars, RAG docs + architecture injected OK")

# Test 3: DAMAGE_PROMPT
t3 = jinja2.Template(DAMAGE_PROMPT)
r3 = t3.render(
    threats='[{"id": "T-01", "nodeId": "bms-cell", "loss": "Integrity", "asset": "CellMonitoring"}]',
    architecture='{"template": {"nodes": [{"id": "bms-cell"}]}}'
)
assert "T-01" in r3
assert "bms-cell" in r3
print(f"[PASS] DAMAGE_PROMPT: {len(r3)} chars, threats + architecture injected OK")

# Test 4: Verify pipeline imports still work
from pipeline import build_graph, _score_section, RAGState
print(f"[PASS] pipeline.py imports OK (build_graph, _score_section, RAGState)")

# Test 5: _score_section excludes groups
mock_state = {
    "architecture": {
        "template": {
            "nodes": [
                {"id": "grp", "type": "group"},
                {"id": "n1", "type": "default"},
                {"id": "n2", "type": "default"},
                {"id": "n3", "type": "default"},
            ]
        }
    },
    "threats": [{"id": "T1"}, {"id": "T2"}, {"id": "T3"}],
    "damage_details": [{"Name": "D1"}, {"Name": "D2"}, {"Name": "D3"}],
    "threat_scenarios": [{"id": "TS1"}, {"id": "TS2"}, {"id": "TS3"}],
}
qc = _score_section(mock_state)
assert qc["node_count"] == 3, f"Expected 3 components (excluding group), got {qc['node_count']}"
assert qc["arch_ok"] == True
print(f"[PASS] _score_section: correctly counts 3 components (ignores 1 group node)")

print("\n" + "=" * 50)
print("  ALL TESTS PASSED")
print("=" * 50)
