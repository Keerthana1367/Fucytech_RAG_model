# Fucytech Automotive RAG Pipeline (TARA Agent)

An agentic Retrieval-Augmented Generation (RAG) pipeline customized for generating ISO 21434 compliant Threat Analysis and Risk Assessment (TARA) JSON reports for Automotive Electronic Control Units (ECUs) such as Battery Management Systems (BMS).

## Overview
This platform employs multiple LangGraph / AI agents to automatically analyze automotive system architecture, identify cybersecurity threats, and generate damage scenarios based on industry standards, outputting a precise JSON format that integrates perfectly with the **TARA X-Press** ReactFlow visualization frontend.

### Agent Workflow
1. **Architect Agent**: Discovers technical bounds and builds the logical ECU architecture (Nodes, Components, Interfaces). Specifically trained to maintain strict adherence to golden reference templates, including required data components like SoC, SoH for BMS.
2. **Threat Analyst Agent (STRIDE)**: Performs Deep technical threat discovery mapping against the generated node architecture to produce realistic system threats.
3. **Damage Analyst Agent**: Assesses derived threat scenarios to compute impact ratings (Financial, Safety, Operational, Privacy) and categorizes cyber loss properties (Integrity, Confidentiality, Authenticity).

## Features
- **Strict Structural Formatting**: Guaranteed ID linkages between cyber loss properties in `Damage_scenarios` and target properties in `Threat_scenarios`, ensuring ReactFlow components remain context-aware and logically bound.
- **Frontend-Ready Asset Edges**: Fallback to safe source handles (e.g. `b`, `left`, `right`) preventing DOM layout crashes on the frontend. Explicit mapping of core MCU nodes to sensory data nodes (e.g. `CellMonitoring`, `IO and Analog` -> `BatteryPack`).
- **UUID Remapper (`_remap`)**: Deterministic and consistent UUIDs across iterations, avoiding fragmented TARA graph instances.
- **Smart Pipeline Cache Recovery**: Individual steps gracefully cache logic to save redundant LLM executions, while allowing selective cache-busting per node.

## Usage

You must have your `GOOGLE_API_KEY` set in your environment.

To run the pipeline and generate a TARA for the Battery Management System (BMS):
```bash
python main.py -q BMS
```

The resulting compliant JSON will be saved to `outputs/results/tara_output_BMS.json`, which can be immediately uploaded to your TARA X-Press frontend.
