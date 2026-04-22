# =============================================================================
# main.py — CLI entry point for TARA LangGraph RAG Pipeline
# =============================================================================

import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from components import (
    resolve_ecu, list_ecus, build_enriched_query,
    parse_and_fix, print_summary,
    EMBED_MODEL, GEMINI_MODEL, RETRIEVER_TOP_K,
)
from ingest import load_all_documents
from pipeline import build_graph





def main():
    parser = argparse.ArgumentParser(
        description="TARA Agentic RAG Pipeline",
    )

    parser.add_argument("--query", "-q", type=str, default=None)
    parser.add_argument("--output", "-o", type=str, default=None)
    parser.add_argument("--no-save", action="store_true")
    parser.add_argument("--list-ecus", action="store_true")

    args = parser.parse_args()

    # ── List ECUs ─────────────────────────────────────────────
    if args.list_ecus:
        list_ecus()
        return

    if not args.query:
        parser.print_help()
        sys.exit(1)

    user_query = args.query.strip()

    print("\n" + "=" * 60)
    print("  TARA Agentic RAG (LangGraph)")
    print("=" * 60)
    print(f"  Query : {user_query}")
    print("=" * 60 + "\n")

    # ── API KEY CHECK ─────────────────────────────────────────
    if "GOOGLE_API_KEY" not in os.environ:
        print("[Error] GOOGLE_API_KEY not set")
        sys.exit(1)

    # ── STEP 1: ECU RESOLUTION ───────────────────────────────
    print("[1/4] Resolving ECU...")
    ecu_entry = resolve_ecu(user_query)

    if ecu_entry:
        name = ecu_entry.get("name") or ecu_entry.get("id", "Unknown")
        print(f"  [Success] Matched : {name}")
    else:
        print("  [Warning] No match found")

    enriched_query = build_enriched_query(user_query, ecu_entry)

    # ── STEP 2: INGEST ───────────────────────────────────────
    print("\n[2/4] Loading documents...")
    all_docs = load_all_documents()

    # ── STEP 3: LANGGRAPH BUILD ──────────────────────────────
    print("\n[3/4] Building LangGraph pipeline...")
    graph = build_graph(all_docs)

    # ── STEP 4: GENERATE ─────────────────────────────────────
    print("\n[4/4] Generating report...")
    print(f"  Embedding model : {EMBED_MODEL}")
    print(f"  LLM model       : {GEMINI_MODEL}")
    print(f"  Retriever top_k : {RETRIEVER_TOP_K}")

    result = graph.invoke({
        "user_query": user_query,
        "enriched_query": enriched_query,
        "retry_count": 0
    })

    raw_output = result["answer"]

    # ── POST PROCESS ─────────────────────────────────────────
    print("\nPost-processing...")
    tara_json = parse_and_fix(raw_output)

    if tara_json is None:
        print("[Error] Failed to parse output")
        print(raw_output[:1000])
        sys.exit(1)

    print("[Success] JSON parsed successfully")
    print_summary(tara_json)

    # ── PRINT OUTPUT ─────────────────────────────────────────
    print("\n" + "-" * 60)
    print(json.dumps(tara_json, indent=2, ensure_ascii=False))
    print("-" * 60)

    # ── SAVE FILE ────────────────────────────────────────────
    if not args.no_save:
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", user_query.strip())
        
        # Directories matching user request
        outputs_dir = Path(__file__).parent / "outputs"
        prompts_dir = outputs_dir / "prompts"
        tara_dir    = outputs_dir / "Results"
        eval_dir    = outputs_dir / "langgraph_evaluation_results"
        
        prompts_dir.mkdir(parents=True, exist_ok=True)
        tara_dir.mkdir(parents=True, exist_ok=True)
        eval_dir.mkdir(parents=True, exist_ok=True)

        # 1. Save Full Prompt for Debugging
        full_prompt = result.get("full_prompt", "")
        # 1. Save TARA JSON output
        tara_output_path = tara_dir / f"tara_output_{safe_name}.json"
        with open(tara_output_path, "w", encoding="utf-8") as f:
            f.write(result["answer"])
            

        
        if full_prompt:
            prompt_path = prompts_dir / f"tara_prompt_{safe_name}.txt"
            with open(prompt_path, "w", encoding="utf-8") as f:
                f.write(full_prompt)
            print(f"  [File] Prompt saved -> {prompt_path}")

        # 2. Save TARA JSON
        out_file = args.output or f"tara_output_{safe_name}.json"
        out_path = tara_dir / out_file
        
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(tara_json, f, indent=2, ensure_ascii=False)
        print(f"[Success] TARA Saved -> {out_path}")

        # 3. Save Evaluation Results
        eval_details = result.get("eval_details", {})
        eval_score   = result.get("eval_score", 0)
        eval_path    = eval_dir / f"eval_report_{safe_name}.json"
        
        with open(eval_path, "w", encoding="utf-8") as f:
            json.dump(eval_details if eval_details else {"score": eval_score}, f, indent=2, ensure_ascii=False)
            
        print(f"  [Stats] Evaluation saved -> {eval_path}")
        print(f"  [Score] Final Score: {eval_score}%")
        print("\n" + "=" * 60)
        print("  TARA GENERATION COMPLETE")
        print("=" * 60 + "\n")


if __name__ == "__main__":
    main()