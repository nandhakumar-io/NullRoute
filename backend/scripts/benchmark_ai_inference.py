"""Reproducible benchmark: sequential vs batched DistilBERT/MiniLM stage.

Measures REAL wall time on this machine. Uses the configured models
(AI_CLASSIFIER_MODEL_PATH / AI_EMBEDDING_MODEL_PATH) or, with --tiny-models,
tiny random-weight models (timing only, meaningless predictions). The LLM stage
is NOT timed: it is replaced by a counting stub, so only LLM *call counts*
are reported.

    python -m scripts.benchmark_ai_inference --tiny-models --copies 20
"""
import argparse, asyncio, glob, json, os, tempfile, time

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tiny-models", action="store_true")
    ap.add_argument("--copies", type=int, default=10, help="repeat each sample config N times (simulates a fleet)")
    ap.add_argument("--configs", default=os.path.join(os.path.dirname(__file__), "..", "..", "sample_configs", "*"))
    a = ap.parse_args()
    if a.tiny_models:
        from scripts.tiny_ai_models import build_both
        d, m = build_both(tempfile.mkdtemp())
        os.environ["AI_CLASSIFIER_MODEL_PATH"], os.environ["AI_EMBEDDING_MODEL_PATH"] = d, m
        ds = os.path.join(tempfile.mkdtemp(), "ds.json")
        json.dump([{"text": "ip ssh version 2", "intent": "ssh_management", "vendor": "cisco"}], open(ds, "w"))
        os.environ["AI_REFERENCE_DATASET"] = ds
        os.environ.pop("AI_CLASSIFIER_REMOTE_URL", None); os.environ.pop("AI_EMBEDDING_REMOTE_URL", None)
    from app.ai import classifier as C, embeddings as E, staged, inference_cache
    from app.ai.decision_engine import DecisionThresholds
    from app.ai.model_registry import AIRegistry
    from app.ai.normalize import AIInterpretation
    from app.services.parsers import parse_config

    clf, emb = C.load_classifier(), E.load_embedder()
    reg = AIRegistry(True, clf, emb, DecisionThresholds(0.75, 0.6), os.getenv("AI_MODEL_VERSION", "bench"))
    lines = []
    for f in sorted(glob.glob(a.configs)):
        if os.path.isfile(f):
            txt = open(f, errors="replace").read()
            for vendor in ("Cisco", "Juniper", "Fortinet"):
                lines += parse_config(vendor, txt).extra_parameters.get("_unknown_lines", [])[:200]
    lines = lines * a.copies
    print(json.dumps({"classifier": clf.backend_name, "embedder": emb.backend_name, "device": clf.device, "total_lines": len(lines), "unique_lines": len(set(lines))}))

    t = time.perf_counter(); n_clf = n_emb = 0
    for l in lines:
        C.classify(clf, l); E.nearest(emb, l); n_clf += 1; n_emb += 1
        if emb.encode_fn: emb.encode_fn(l); n_emb += 1  # the old pipeline embedded a second time for RAG
    seq = time.perf_counter() - t

    llm_calls = []
    async def llm(v, l, r):
        llm_calls.append(l); return [AIInterpretation(l, "a.b", True, 0.9, [], "stub", False)]
    inference_cache.reset_cache_for_tests()
    items = [staged.InferenceItem(line=l, vendor="Cisco", tenant_id="t") for l in lines]
    run = lambda: asyncio.run(staged.normalize_unknown_lines(items, db=None, interpret_fn=llm, registry=reg, retrieve_fn=lambda *x, **k: []))
    t = time.perf_counter(); _, cold = run(); cold_s = time.perf_counter() - t
    t = time.perf_counter(); _, warm = run(); warm_s = time.perf_counter() - t
    # Dedup-free comparison (each unique line once): isolates the batching gain.
    uniq = list(dict.fromkeys(lines))
    t = time.perf_counter()
    for l in uniq:
        C.classify(clf, l); E.nearest(emb, l)
        if emb.encode_fn: emb.encode_fn(l)
    seq_u = time.perf_counter() - t
    inference_cache.reset_cache_for_tests()
    uitems = [staged.InferenceItem(line=l, vendor="Cisco", tenant_id="t") for l in uniq]
    t = time.perf_counter()
    asyncio.run(staged.normalize_unknown_lines(uitems, db=None, interpret_fn=llm, registry=reg, retrieve_fn=lambda *x, **k: []))
    stg_u = time.perf_counter() - t
    print(json.dumps({"unique_only_sequential_s": round(seq_u, 4), "unique_only_staged_cold_s": round(stg_u, 4), "unique_lines": len(uniq)}))
    print(json.dumps({"sequential_s": round(seq, 4), "sequential_classifier_calls": n_clf, "sequential_embedder_calls": n_emb,
                      "staged_cold_s": round(cold_s, 4), "staged_warm_cache_s": round(warm_s, 4),
                      "cold_stats": cold.as_dict(), "warm_stats": warm.as_dict(), "stub_llm_calls_total": len(llm_calls)}, indent=1))

if __name__ == "__main__":
    main()