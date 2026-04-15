import json
import os

def debug_json():
    json_path = os.path.join("outputs", "Results", "tara_output_BMS_System.json")
    if not os.path.exists(json_path):
        print(f"File not found: {json_path}")
        return

    with open(json_path, "r") as f:
        data = json.load(f)

    nodes = data.get("Assets", {}).get("template", {}).get("nodes", [])
    print(f"Nodes found: {len(nodes)}")
    
    ds_details = data.get("Damage_scenarios", [{}])[0].get("Details", [])
    print(f"Damage Scenarios found: {len(ds_details)}")
    
    ts_root = data.get("Threat_scenarios", [{}])[0].get("Details", [])
    ts_list = []
    for group in ts_root:
        ts_list.extend(group.get("Details", []))
    print(f"Threat Scenarios found: {len(ts_list)}")

    if ds_details:
        print("Sample Damage Scenario Impacts:")
        print(ds_details[0].get("impacts"))

if __name__ == "__main__":
    debug_json()
