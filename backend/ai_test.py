import os
import json
from app.ai.embeddings import load_embedder, nearest

def test_embeddings():
    print(f"Checking configured Dataset... {os.environ.get('AI_REFERENCE_DATASET')}")
    try:
        with open(os.environ.get('AI_REFERENCE_DATASET')) as f:
            print("Dataset successfully loaded internally:", len(json.load(f)), "items found.")
    except Exception as e:
        print("Failed to read dataset inside container:", e)

    print("Testing ML semantic similarity retrieval...")
    loaded = load_embedder()
    match, latency = nearest(loaded, "snmp-server community public ro")
    
    print(f"Match: {match.nearest_intent} (Score: {match.similarity:.2f})")
    print(f"Latency: {latency:.1f}ms")

if __name__ == "__main__":
    test_embeddings()
