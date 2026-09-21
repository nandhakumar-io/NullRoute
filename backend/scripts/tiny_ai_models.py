"""
Builds TINY, RANDOMLY-INITIALISED stand-ins for the DistilBERT classifier and
the MiniLM embedder, entirely offline (no downloads).

Purpose: exercise the *real* torch / transformers / sentence-transformers code
paths in app/ai/classifier.py and app/ai/embeddings.py -- padding, batching,
device handling, ordering -- in tests and in the throughput benchmark, on any
machine (CPU-only CI, 2 vCPU VM) without needing the production checkpoints.

They are NOT trained. Their predictions carry no meaning, so they are only
valid for equivalence ("batched == sequential") and timing checks. Never use
them to judge classification quality; that is what the frozen evaluation set
and the real checkpoint are for.
"""
from __future__ import annotations

import os
from typing import List, Optional

from app.ai.classifier import KNOWN_INTENTS

_WORDS = (
    "ip ssh version 2 logging host ntp server snmp community ro rw aaa new model authentication login default group "
    "radius tacacs local interface gigabitethernet0 1 switchport access vlan router ospf bgp access list acl banner "
    "motd password secret enable service telnet http https transport input line vty exec timeout no shutdown "
    "set system services protocol syslog any warning config end edit next name admin trap source permit deny "
    "10 20 30 0 4 5 8 24 16 100 200 500 unknown directive foo bar baz ambiguous".split()
)
SPECIALS = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]"]


def _vocab() -> List[str]:
    seen, out = set(), list(SPECIALS)
    for w in _WORDS:
        if w not in seen:
            seen.add(w)
            out.append(w)
    return out


def _write_vocab(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    vocab_file = os.path.join(path, "vocab.txt")
    with open(vocab_file, "w", encoding="utf-8") as f:
        f.write("\n".join(_vocab()) + "\n")
    return vocab_file


def build_tiny_distilbert(path: str, seed: int = 0) -> str:
    """Write a tiny DistilBERT sequence classifier (13 intent labels) to `path`."""
    import torch
    from transformers import DistilBertConfig, DistilBertForSequenceClassification, DistilBertTokenizerFast

    vocab_file = _write_vocab(path)
    tokenizer = DistilBertTokenizerFast(vocab_file=vocab_file, do_lower_case=True)
    torch.manual_seed(seed)
    config = DistilBertConfig(
        vocab_size=len(_vocab()), dim=32, n_layers=2, n_heads=2, hidden_dim=64,
        max_position_embeddings=64, num_labels=len(KNOWN_INTENTS),
        id2label={i: name for i, name in enumerate(KNOWN_INTENTS)},
        label2id={name: i for i, name in enumerate(KNOWN_INTENTS)},
        pad_token_id=0,
    )
    model = DistilBertForSequenceClassification(config)
    model.save_pretrained(path)
    tokenizer.save_pretrained(path)
    return path


def build_tiny_minilm(path: str, seed: int = 0) -> str:
    """Write a tiny sentence-transformers model (BERT + mean pooling + L2 norm) to `path`."""
    import torch
    from sentence_transformers import SentenceTransformer, models
    from transformers import BertConfig, BertModel, BertTokenizerFast

    hf_dir = os.path.join(path, "_hf")
    vocab_file = _write_vocab(hf_dir)
    tokenizer = BertTokenizerFast(vocab_file=vocab_file, do_lower_case=True)
    torch.manual_seed(seed)
    config = BertConfig(
        vocab_size=len(_vocab()), hidden_size=32, num_hidden_layers=2, num_attention_heads=2,
        intermediate_size=64, max_position_embeddings=128, pad_token_id=0,
    )
    BertModel(config).save_pretrained(hf_dir)
    tokenizer.save_pretrained(hf_dir)

    transformer = models.Transformer(hf_dir, max_seq_length=64)
    pooling = models.Pooling(transformer.get_word_embedding_dimension(), pooling_mode="mean")
    st = SentenceTransformer(modules=[transformer, pooling, models.Normalize()], device="cpu")
    st.save(path)
    return path


def build_both(root: str, seed: int = 0) -> tuple[str, str]:
    return (
        build_tiny_distilbert(os.path.join(root, "distilbert"), seed),
        build_tiny_minilm(os.path.join(root, "minilm"), seed),
    )