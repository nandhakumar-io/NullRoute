"""Batched DistilBERT / MiniLM inference vs the sequential path, on real
(tiny, random-weight, offline) torch models. Equivalence only -- not quality."""
import json
import os

import pytest

pytest.importorskip("torch")
pytest.importorskip("transformers")
pytest.importorskip("sentence_transformers")

from app.ai import classifier as clf_mod, embeddings as emb_mod, settings as ai_settings  # noqa: E402
from scripts.tiny_ai_models import build_both  # noqa: E402

TEXTS = [
    "ip ssh version 2", "logging host 10.10.10.10", "snmp-server community ro", "ntp server 10.10.10.20",
    "unknown directive foo bar baz", "line vty 0 4 transport input telnet", "banner motd x",
    "aaa authentication login default group radius local", "router ospf 1", "no shutdown", "set system syslog host 10.1.1.1 any warning",
]


@pytest.fixture(scope="module")
def models(tmp_path_factory):
    root = tmp_path_factory.mktemp("tiny")
    dpath, mpath = build_both(str(root))
    ds = root / "ds.json"
    ds.write_text(json.dumps([{"text": "ip ssh version 2", "intent": "ssh_management", "vendor": "cisco"}]))
    return dpath, mpath, str(ds)


@pytest.fixture()
def clf(models, monkeypatch):
    monkeypatch.setenv("AI_DEVICE", "cpu")
    loaded = clf_mod._try_load_distilbert(models[0])
    assert loaded is not None
    return loaded


@pytest.fixture()
def emb(models, monkeypatch):
    monkeypatch.setenv("AI_DEVICE", "cpu")
    loaded = emb_mod._try_load_minilm(models[1], models[2], None)
    assert loaded is not None
    return loaded


def _same(a, b):
    assert a.intent == b.intent
    assert abs(a.confidence - b.confidence) <= 2e-4
    assert a.model_version == b.model_version


@pytest.mark.parametrize("bs", [1, 3, 4, 100])  # smaller than, equal-ish to, and larger than the input count
def test_distilbert_batch_equals_sequential_and_keeps_order(clf, monkeypatch, bs):
    monkeypatch.setenv("AI_DISTILBERT_BATCH_SIZE", str(bs))
    seq = [clf.predict_fn(t) for t in TEXTS]
    bat, ms = clf_mod.classify_batch(clf, TEXTS)
    assert len(bat) == len(TEXTS) and ms >= 0
    for s, b in zip(seq, bat):
        _same(s, b)
    rev, _ = clf_mod.classify_batch(clf, list(reversed(TEXTS)))
    for s, b in zip(reversed(seq), rev):
        _same(s, b)


def test_distilbert_empty_and_single(clf):
    assert clf_mod.classify_batch(clf, [])[0] == []
    one, _ = clf_mod.classify_batch(clf, [TEXTS[0]])
    _same(one[0], clf.predict_fn(TEXTS[0]))


def test_distilbert_uses_chunks_of_configured_size(models, monkeypatch):
    from transformers import AutoModelForSequenceClassification as M
    sizes = []
    orig = M.from_pretrained

    def spy(*a, **k):
        m = orig(*a, **k)
        m.register_forward_hook(lambda mod, args, kwargs, out: sizes.append(kwargs["input_ids"].shape[0]), with_kwargs=True)
        return m

    monkeypatch.setattr(M, "from_pretrained", spy)
    monkeypatch.setenv("AI_DEVICE", "cpu")
    monkeypatch.setenv("AI_DISTILBERT_BATCH_SIZE", "4")
    loaded = clf_mod._try_load_distilbert(models[0])
    clf_mod.classify_batch(loaded, TEXTS)  # 11 texts
    assert sizes == [4, 4, 3]


def test_distilbert_oom_backs_off_without_dropping(models, monkeypatch):
    monkeypatch.setenv("AI_DEVICE", "cpu")
    loaded = clf_mod._try_load_distilbert(models[0])
    expected = [loaded.predict_fn(t) for t in TEXTS]
    from transformers import DistilBertForSequenceClassification as D
    real = D.forward

    def flaky(self, *a, **k):
        if k["input_ids"].shape[0] > 2:
            raise RuntimeError("CUDA out of memory")
        return real(self, *a, **k)

    monkeypatch.setattr(D, "forward", flaky)
    got, _ = clf_mod.classify_batch(loaded, TEXTS)
    for s, b in zip(expected, got):
        _same(s, b)


def test_non_resource_error_is_raised(models, monkeypatch):
    monkeypatch.setenv("AI_DEVICE", "cpu")
    loaded = clf_mod._try_load_distilbert(models[0])
    from transformers import DistilBertForSequenceClassification as D
    monkeypatch.setattr(D, "forward", lambda self, *a, **k: (_ for _ in ()).throw(ValueError("boom")))
    with pytest.raises(ValueError):
        clf_mod.classify_batch(loaded, TEXTS)


def test_cpu_only_device_selection(monkeypatch, clf):
    import torch
    assert clf.device == "cpu"
    monkeypatch.delenv("AI_DEVICE", raising=False)
    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)
    assert ai_settings.resolve_torch_device() == "cpu"
    monkeypatch.setattr(torch.cuda, "is_available", lambda: True)
    assert ai_settings.resolve_torch_device() == "cuda"
    monkeypatch.setenv("AI_DEVICE", "cpu")
    assert ai_settings.resolve_torch_device() == "cpu"


@pytest.mark.parametrize("bs", [1, 4, 100])
def test_minilm_batch_equals_sequential(emb, monkeypatch, bs):
    import numpy as np
    monkeypatch.setenv("AI_MINILM_BATCH_SIZE", str(bs))
    vecs, _ = emb_mod.embed_batch(emb, TEXTS)
    assert len(vecs) == len(TEXTS)
    for t, v in zip(TEXTS, vecs):
        s = emb.encode_fn(t)
        assert len(v) == len(s) == 32
        assert np.allclose(v, s, atol=1e-5)
        assert abs(np.linalg.norm(v) - 1.0) < 1e-4  # normalize_embeddings preserved
    rev, _ = emb_mod.embed_batch(emb, list(reversed(TEXTS)))
    assert np.allclose(rev, list(reversed(vecs)), atol=1e-5)


def test_minilm_empty_single_and_batch_size_passed(emb, monkeypatch):
    assert emb_mod.embed_batch(emb, [])[0] == []
    assert len(emb_mod.embed_batch(emb, ["ip ssh version 2"])[0]) == 1
    from sentence_transformers import SentenceTransformer
    seen = {}
    orig = SentenceTransformer.encode

    def spy(self, sentences, *a, **k):
        seen.update(k)
        return orig(self, sentences, *a, **k)

    monkeypatch.setattr(SentenceTransformer, "encode", spy)
    monkeypatch.setenv("AI_MINILM_BATCH_SIZE", "7")
    emb_mod.embed_batch(emb, TEXTS)
    assert seen["batch_size"] == 7 and seen["normalize_embeddings"] is True


def test_nearest_from_vector_matches_nearest(emb):
    for t in TEXTS:
        m1, _ = emb_mod.nearest(emb, t)
        m2 = emb_mod.nearest_from_vector(emb, t, emb.encode_fn(t))
        assert m1 == m2


def test_keyword_fallback_and_remote_fanout_preserve_order(monkeypatch):
    kw = clf_mod.LoadedClassifier("keyword-fallback", "v", clf_mod._keyword_predict("v"))
    res, _ = clf_mod.classify_batch(kw, TEXTS)
    assert [r.intent for r in res] == [kw.predict_fn(t).intent for t in TEXTS]

    import io, urllib.request

    class R(io.BytesIO):
        __enter__ = lambda s: s
        __exit__ = lambda s, *a: None

    def fake_urlopen(req, timeout=0):
        text = json.loads(req.data)["text"]
        return R(json.dumps({"result": {"label": "SSH " + text, "score": 0.9}, "model": "m"}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    remote = clf_mod._try_load_remote_classifier("http://x/classify", "", 1.0)
    monkeypatch.setenv("AI_REMOTE_INFERENCE_CONCURRENCY", "4")
    out, _ = clf_mod.classify_batch(remote, TEXTS)
    assert [r.intent for r in out] == [("ssh " + t).lower().replace(" ", "_") for t in TEXTS]