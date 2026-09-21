"""Staged normalization: dedup, cache, routing, provenance, validation."""
import logging
import re

import httpx
import pytest
import respx

from app.ai import inference_cache, normalize as nz, staged
from app.ai.classifier import LoadedClassifier
from app.ai.decision_engine import DecisionThresholds
from app.ai.embeddings import LoadedEmbedder, ReferenceExample
from app.ai.model_registry import AIRegistry
from app.ai.normalize import AIInterpretation
from app.ai.schemas import ClassifierResult
from app.services.parsers import parse_config

pytestmark = pytest.mark.asyncio


class Counters:
    def __init__(self):
        self.clf_batches, self.clf_texts, self.emb_batches, self.emb_texts = 0, [], 0, []


def make_registry(c: Counters, conf=0.9, version="reg-v1", clf_version="clf-v1"):
    def clf_batch(texts):
        c.clf_batches += 1
        c.clf_texts.extend(texts)
        return [ClassifierResult(intent="ssh_management", confidence=conf, model_version=clf_version) for _ in texts]

    def emb_batch(texts):
        c.emb_batches += 1
        c.emb_texts.extend(texts)
        return [[float(len(t)), 1.0] for t in texts]

    clf = LoadedClassifier("distilbert", clf_version, lambda t: clf_batch([t])[0], predict_batch_fn=clf_batch)
    ex = [ReferenceExample("ip ssh version 2", "ssh_management", "cisco", [10.0, 1.0])]
    emb = LoadedEmbedder("minilm", "emb-v1", None, ex, encode_fn=lambda t: emb_batch([t])[0], encode_batch_fn=emb_batch)
    return AIRegistry(True, clf, emb, DecisionThresholds(0.75, 0.6), version)


class FakeLLM:
    def __init__(self, conf=0.9, param="management.ssh.enabled"):
        self.calls, self.conf, self.param = [], conf, param

    async def __call__(self, vendor, line, retrieved):
        self.calls.append((vendor, line, list(retrieved)))
        return [AIInterpretation(line, self.param, True, self.conf, [k["pattern"] for k in retrieved], "llm-x",
                                 self.conf < nz.CONFIDENCE_THRESHOLD, "r")]


def items(lines, vendor="Cisco", tenant="t1"):
    return [staged.InferenceItem(line=l, vendor=vendor, tenant_id=tenant, device_id="d") for l in lines]


def no_retrieval(db, vendor, line, vec, tenant_id=None):
    return []


async def run(lines, llm, reg, retrieve=no_retrieval, **kw):
    return await staged.normalize_unknown_lines(items(lines, **kw), db=None, interpret_fn=llm, registry=reg, retrieve_fn=retrieve)


async def test_empty_and_single():
    reg, llm = make_registry(Counters()), FakeLLM()
    assert (await run([], llm, reg))[0] == []
    res, st = await run(["ip ssh version 2"], llm, reg)
    assert len(res) == 1 and st.llm_calls == 1 and st.unique_inputs == 1


async def test_dedup_runs_models_once_and_fans_out_in_order():
    c, llm = Counters(), FakeLLM()
    lines = ["logging host 10.10.10.10"] * 100 + ["ntp server 1.1.1.1"] + ["logging host 10.10.10.10"]
    res, st = await run(lines, llm, make_registry(c))
    assert len(res) == 102 and [r.index for r in res] == list(range(102))
    assert [r.item.line for r in res] == lines
    assert st.unique_inputs == 2 and st.duplicates_eliminated == 100
    assert len(llm.calls) == 2 and sorted(c.clf_texts) == sorted(set(lines)) and c.clf_batches == 1 and c.emb_batches == 1
    res[0].interpretations[0].value = "mutated"  # occurrences must not alias each other
    assert res[1].interpretations[0].value is True


async def test_context_prevents_false_dedup():
    llm = FakeLLM()
    reg = make_registry(Counters())
    items_ = items(["x y"], vendor="Cisco") + items(["x y"], vendor="Juniper") + items(["x y"], tenant="t2")
    _, st = await staged.normalize_unknown_lines(items_, db=None, interpret_fn=llm, registry=reg, retrieve_fn=no_retrieval)
    assert st.unique_inputs == 3 and len(llm.calls) == 3


async def test_llm_gets_full_context_and_single_embed_reuse():
    c, llm, seen = Counters(), FakeLLM(), []

    def retrieve(db, vendor, line, vec, tenant_id=None):
        seen.append((vec, tenant_id))
        return [{"pattern": "p", "parameter": "a.b", "example_value": "1"}]

    res, _ = await run(["some line"], llm, make_registry(c), retrieve)
    assert llm.calls[0][:2] == ("Cisco", "some line") and llm.calls[0][2][0]["pattern"] == "p"
    assert seen == [([float(len("some line")), 1.0], "t1")]  # retrieval reused the batch vector
    assert c.emb_texts == ["some line"]  # embedded exactly once


async def test_cache_hit_miss_and_provenance():
    llm, reg = FakeLLM(), make_registry(Counters())
    r1, s1 = await run(["ip ssh version 2"], llm, reg)
    r2, s2 = await run(["ip ssh version 2"], llm, reg)
    assert len(llm.calls) == 1
    assert (s1.interpretation_cache_misses, s1.interpretation_cache_hits) == (1, 0)
    assert (s2.interpretation_cache_hits, s2.llm_calls) == (1, 0)
    assert r1[0].route == staged.ROUTE_LLM and r2[0].route == staged.ROUTE_CACHE_HIT and r2[0].cache_hit
    p = r2[0].provenance
    assert p["classifier"]["intent"] == "ssh_management" and p["classifier"]["backend"] == "distilbert"
    assert p["embedding"]["model_version"] == "emb-v1" and p["llm"]["model"] == nz.LLM_MODEL
    assert p["llm"]["prompt_fingerprint"] == nz.prompt_fingerprint() and "retrieval" in p
    assert s2.classifier_cache_hits == 1 and s2.embedder_cache_hits == 1  # model caches too


@pytest.mark.parametrize("change", ["registry", "classifier", "llm", "prompt", "retrieval", "tenant"])
async def test_cache_invalidated_on_version_change(change, monkeypatch):
    llm, c = FakeLLM(), Counters()
    await run(["ip ssh version 2"], llm, make_registry(c))
    kw, reg, retr = {}, make_registry(c), no_retrieval
    if change == "registry":
        reg = make_registry(c, version="reg-v2")
    elif change == "classifier":
        reg = make_registry(c, clf_version="clf-v2")
    elif change == "llm":
        monkeypatch.setattr(nz, "LLM_MODEL", "other-model")
    elif change == "prompt":
        monkeypatch.setattr(nz, "KNOWN_PARAMETERS", nz.KNOWN_PARAMETERS + ["new.param"])
    elif change == "retrieval":  # a human approved/corrected a mapping
        retr = lambda db, v, l, vec, tenant_id=None: [{"pattern": "ip ssh version 2", "parameter": "a", "example_value": "2"}]
    elif change == "tenant":
        kw = {"tenant": "t2"}
    await run(["ip ssh version 2"], llm, reg, retr, **kw)
    assert len(llm.calls) == 2


async def test_uncertain_and_degraded_results_are_never_cached_and_go_to_review():
    llm = FakeLLM(conf=0.4)
    reg = make_registry(Counters())
    r1, s1 = await run(["weird"], llm, reg)
    r2, s2 = await run(["weird"], llm, reg)
    assert len(llm.calls) == 2 and r1[0].route == staged.ROUTE_REVIEW and s1.human_review_lines == 1
    assert r1[0].interpretations[0].needs_human_review

    async def degraded(v, l, r):
        return [AIInterpretation(l, "a.b", True, 0.9, [], "m+llama_unavailable", False, "d")]

    calls = []
    for _ in range(2):
        await staged.normalize_unknown_lines(items(["deg"]), db=None, interpret_fn=lambda v, l, r: (calls.append(1), degraded(v, l, r))[1],
                                             registry=reg, retrieve_fn=no_retrieval)
    assert len(calls) == 2


async def test_cache_disabled(monkeypatch):
    monkeypatch.setenv("AI_INFERENCE_CACHE_ENABLED", "false")
    llm, reg = FakeLLM(), make_registry(Counters())
    await run(["a b"], llm, reg)
    await run(["a b"], llm, reg)
    assert len(llm.calls) == 2


async def test_high_classifier_confidence_alone_does_not_skip_llm():
    llm = FakeLLM()
    res, _ = await run(["ip ssh version 2"], llm, make_registry(Counters(), conf=0.99))
    assert res[0].analysis.decision == "KNOWN_CANDIDATE" and len(llm.calls) == 1


def approved(pattern="legacy-on", param="management.telnet.enabled", value="True", conf=0.95, mid="m1"):
    return lambda db, v, l, vec, tenant_id=None: [{"pattern": pattern, "parameter": param, "example_value": value,
                                                   "mapping_id": mid, "mapping_confidence": conf, "similarity": 1.0}]


async def test_approved_mapping_shortcut_is_opt_in_exact_and_typed(monkeypatch):
    llm, reg = FakeLLM(), make_registry(Counters())
    await run(["legacy-on"], llm, reg, approved())
    assert len(llm.calls) == 1  # default OFF
    monkeypatch.setenv("AI_RETRIEVAL_SHORTCUT_ENABLED", "true")
    inference_cache.reset_cache_for_tests()
    res, st = await run(["legacy-on"], llm, reg, approved())
    assert len(llm.calls) == 1 and st.approved_mapping_reuses == 1
    i = res[0].interpretations[0]
    assert i.value is True and not i.needs_human_review
    assert res[0].route == staged.ROUTE_APPROVED_MAPPING and res[0].provenance["approved_mapping_id"] == "m1"
    # weak (non-exact) match, conflicting matches, missing confidence -> LLM
    for retr in (approved(pattern="legacy-off"), approved(conf=None),
                 lambda *a, **k: approved()(*a)[:1] + approved(param="x.y")(*a)):
        before = len(llm.calls)
        await run(["legacy-on"], llm, reg, retr)
        assert len(llm.calls) == before + 1


async def test_checkpoint_between_chunks_and_stats(monkeypatch):
    monkeypatch.setenv("AI_NORMALIZE_CHUNK_SIZE", "4")
    n = []

    async def cp():
        n.append(1)

    llm = FakeLLM()
    res, st = await staged.normalize_unknown_lines(items([f"l{i}" for i in range(10)]), db=None, interpret_fn=llm,
                                                   registry=make_registry(Counters()), retrieve_fn=no_retrieval, checkpoint=cp)
    assert st.chunks == 3 and len(n) == 2 and [r.item.line for r in res] == [f"l{i}" for i in range(10)]


async def test_ai_disabled_still_interprets_and_marks_analysis_unknown():
    reg = AIRegistry(False, None, None, DecisionThresholds(0.75, 0.6), "x")
    llm = FakeLLM()
    res, _ = await run(["a b"], llm, reg)
    assert res[0].analysis.decision == "UNKNOWN" and len(llm.calls) == 1


async def test_optimized_equals_sequential_interpretation_on_real_config():
    cfg = "hostname a\nip ssh version 2\nfoo-bar enable\nfoo-bar enable\nsome-unknown-directive x y z\n"
    base = parse_config("Cisco", cfg)
    lines = base.extra_parameters["_unknown_lines"] * 3
    llm = FakeLLM()
    res, _ = await run(lines, llm, make_registry(Counters()))
    for r in res:
        ref = await FakeLLM()("Cisco", r.item.line, [])
        assert [(i.normalized_parameter, i.value, i.confidence, i.needs_human_review) for i in r.interpretations] == \
               [(i.normalized_parameter, i.value, i.confidence, i.needs_human_review) for i in ref]
    assert len(llm.calls) == len(set(lines))


# ---- structured-output validation & logging -------------------------------

@pytest.mark.parametrize("bad", [1.7, -0.1, float("nan"), True, "high", None])
def test_parse_llm_confidence_rejects(bad):
    with pytest.raises((ValueError, TypeError)):
        nz.parse_llm_confidence(bad)


@pytest.mark.parametrize("item", ["str", {"normalized_parameter": ""}, {"normalized_parameter": {"a": 1}},
                                  {"normalized_parameter": "a.b", "confidence": 5}])
def test_validate_llm_item_rejects(item):
    with pytest.raises(ValueError):
        nz.validate_llm_item(item)


@respx.mock
async def test_invalid_llm_output_is_forced_to_review_not_repaired(monkeypatch, caplog):
    monkeypatch.setenv("AI_LLM_MAX_ATTEMPTS", "1")
    line = "snmp-server community SUPERSECRET rw"
    respx.post(f"{nz.OLLAMA_HOST}/generate").mock(return_value=httpx.Response(200, json={"response":
        '{"interpretations":[{"normalized_parameter":"snmp.enabled","value":true,"confidence":1.7}]}'}))
    with caplog.at_level(logging.DEBUG):
        out = await nz.interpret_line("Cisco", line, [])
    assert out and all(i.needs_human_review for i in out) and "unavailable" in out[0].model_version
    assert "SUPERSECRET" not in caplog.text