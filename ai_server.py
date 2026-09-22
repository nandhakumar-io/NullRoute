import os
import gc
import asyncio

import torch
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from huggingface_hub import snapshot_download

from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    BitsAndBytesConfig,
    pipeline,
)

from sentence_transformers import SentenceTransformer


# ============================================================
# CONFIGURATION
# ============================================================

QWEN_MODEL = os.getenv(
    "QWEN_MODEL",
    "Qwen/Qwen3-8B"
)

DISTILBERT_MODEL = os.getenv(
    "DISTILBERT_MODEL",
    "kenpachi-zaraki36/netsecauditor-distilbert-v06"
)

MINILM_MODEL = os.getenv(
    "MINILM_MODEL",
    "kenpachi-zaraki36/netsecauditor-minilm-v02"
)

HF_TOKEN = os.getenv("HF_TOKEN", "")

MAX_INPUT_TOKENS = int(
    os.getenv("QWEN_MAX_INPUT_TOKENS", "4096")
)

MAX_NEW_TOKENS = int(
    os.getenv("QWEN_MAX_NEW_TOKENS", "256")
)


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title="NetSecAuditor Unified AI Server",
    version="1.0.0"
)


# ============================================================
# REQUEST MODELS
# ============================================================

class TextRequest(BaseModel):
    text: str


class GenerateRequest(BaseModel):
    prompt: str
    system: str | None = None
    max_new_tokens: int | None = None
    temperature: float = 0.1


# ============================================================
# GPU
# ============================================================

if not torch.cuda.is_available():
    raise RuntimeError("CUDA GPU is required.")

GPU_NAME = torch.cuda.get_device_name(0)

print("=" * 70)
print("NetSecAuditor Unified AI Server")
print("=" * 70)
print(f"GPU: {GPU_NAME}")
print(f"CUDA: {torch.version.cuda}")
print("=" * 70)


# ============================================================
# HUGGING FACE DOWNLOAD
# ============================================================

def pull_model(model_name: str, model_type: str):

    print()
    print("=" * 70)
    print(f"Checking {model_type}")
    print(f"Model: {model_name}")
    print("=" * 70)

    if HF_TOKEN:
        print("Using Hugging Face authentication.")
    else:
        print("No HF_TOKEN supplied. Public models only.")

    try:

        local_path = snapshot_download(
            repo_id=model_name,
            token=HF_TOKEN if HF_TOKEN else None,
            resume_download=True,
        )

        print(f"{model_type} downloaded/cached successfully:")
        print(local_path)

        return local_path

    except Exception as e:

        print(f"FAILED to download {model_type}")
        print(str(e))

        raise RuntimeError(
            f"Could not download {model_type}: {model_name}"
        ) from e


# ============================================================
# PULL ALL THREE MODELS
# ============================================================

print()
print("=" * 70)
print("DOWNLOADING / VERIFYING AI MODELS")
print("=" * 70)


QWEN_PATH = pull_model(
    QWEN_MODEL,
    "Qwen"
)


DISTILBERT_PATH = pull_model(
    DISTILBERT_MODEL,
    "DistilBERT"
)


MINILM_PATH = pull_model(
    MINILM_MODEL,
    "MiniLM"
)


print()
print("=" * 70)
print("ALL MODELS AVAILABLE LOCALLY")
print("=" * 70)


# ============================================================
# LOAD QWEN
# ============================================================

print()
print("=" * 70)
print("Loading Qwen")
print(f"Path: {QWEN_PATH}")
print("=" * 70)


qwen_quant_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.float16,
    bnb_4bit_use_double_quant=True,
)


qwen_tokenizer = AutoTokenizer.from_pretrained(
    QWEN_PATH,
    trust_remote_code=True,
)


qwen_model = AutoModelForCausalLM.from_pretrained(
    QWEN_PATH,
    quantization_config=qwen_quant_config,
    device_map="auto",
    dtype=torch.float16,
    trust_remote_code=True,
)


qwen_model.eval()


print("Qwen loaded successfully.")

print(
    f"VRAM allocated: "
    f"{torch.cuda.memory_allocated() / 1024**3:.2f} GB"
)

print(
    f"VRAM reserved: "
    f"{torch.cuda.memory_reserved() / 1024**3:.2f} GB"
)


# ============================================================
# LOAD DISTILBERT
# ============================================================

print()
print("=" * 70)
print("Loading DistilBERT")
print(f"Path: {DISTILBERT_PATH}")
print("=" * 70)


distilbert_pipe = pipeline(
    "text-classification",
    model=DISTILBERT_PATH,
    device=0,
)


print("DistilBERT loaded successfully.")


# ============================================================
# LOAD MINILM
# ============================================================

print()
print("=" * 70)
print("Loading MiniLM")
print(f"Path: {MINILM_PATH}")
print("=" * 70)


minilm_model = SentenceTransformer(
    MINILM_PATH,
    device="cuda",
)


print("MiniLM loaded successfully.")

print(
    "Embedding dimension:",
    minilm_model.get_sentence_embedding_dimension()
)


# ============================================================
# QWEN CONCURRENCY LIMIT
# ============================================================

# Only one Qwen generation at a time.
# This prevents KV-cache related CUDA OOM.

qwen_semaphore = asyncio.Semaphore(1)


# ============================================================
# QWEN GENERATION
# ============================================================

def generate_qwen(
    prompt: str,
    system: str | None,
    max_new_tokens: int,
    temperature: float,
):

    messages = []

    if system:

        messages.append({
            "role": "system",
            "content": system,
        })

    messages.append({
        "role": "user",
        "content": prompt,
    })


    text = qwen_tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True,
    )


    inputs = qwen_tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        max_length=MAX_INPUT_TOKENS,
    )


    inputs = {
        key: value.to(qwen_model.device)
        for key, value in inputs.items()
    }


    try:

        with torch.inference_mode():

            kwargs = {
                "max_new_tokens": max_new_tokens,
                "use_cache": True,
                "top_p": 0.9,
                "repetition_penalty": 1.05,
                "pad_token_id": qwen_tokenizer.eos_token_id,
            }

            if temperature > 0:

                kwargs["do_sample"] = True
                kwargs["temperature"] = temperature

            else:

                kwargs["do_sample"] = False


            outputs = qwen_model.generate(
                **inputs,
                **kwargs,
            )


        input_length = inputs["input_ids"].shape[1]

        generated_tokens = outputs[0][input_length:]

        response = qwen_tokenizer.decode(
            generated_tokens,
            skip_special_tokens=True,
        )


        return response.strip()


    finally:

        del inputs

        if "outputs" in locals():
            del outputs

        gc.collect()

        torch.cuda.empty_cache()


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "online",

        "gpu": GPU_NAME,

        "cuda": torch.version.cuda,

        "models": {

            "qwen": {
                "status": "loaded",
                "model": QWEN_MODEL,
            },

            "distilbert": {
                "status": "loaded",
                "model": DISTILBERT_MODEL,
            },

            "minilm": {
                "status": "loaded",
                "model": MINILM_MODEL,
                "embedding_dimension":
                    minilm_model.get_sentence_embedding_dimension(),
            },
        },

        "vram": {

            "allocated_gb": round(
                torch.cuda.memory_allocated()
                / 1024**3,
                2
            ),

            "reserved_gb": round(
                torch.cuda.memory_reserved()
                / 1024**3,
                2
            ),

            "total_gb": round(
                torch.cuda.get_device_properties(0).total_memory
                / 1024**3,
                2
            ),
        },

        "qwen_generation_concurrency": 1,
    }


# ============================================================
# DISTILBERT
# ============================================================

@app.post("/classify")
async def classify(req: TextRequest):

    if not req.text.strip():

        raise HTTPException(
            status_code=400,
            detail="Text cannot be empty.",
        )

    try:

        result = await run_in_threadpool(
            distilbert_pipe,
            req.text,
        )

        return {
            "model": "DistilBERT",
            "model_id": DISTILBERT_MODEL,
            "result": result[0],
        }

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=str(e),
        )


# ============================================================
# MINILM
# ============================================================

@app.post("/embed")
async def embed(req: TextRequest):

    if not req.text.strip():

        raise HTTPException(
            status_code=400,
            detail="Text cannot be empty.",
        )

    try:

        embedding = await run_in_threadpool(
            minilm_model.encode,
            req.text,
            normalize_embeddings=True,
        )

        return {
            "model": "MiniLM",
            "model_id": MINILM_MODEL,
            "vector_length": len(embedding),
            "embedding": embedding.tolist(),
        }

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=str(e),
        )


# ============================================================
# QWEN
# ============================================================

@app.post("/generate")
async def generate(req: GenerateRequest):

    if not req.prompt.strip():

        raise HTTPException(
            status_code=400,
            detail="Prompt cannot be empty.",
        )


    requested_tokens = (
        req.max_new_tokens
        if req.max_new_tokens is not None
        else MAX_NEW_TOKENS
    )


    max_new_tokens = min(
        max(1, requested_tokens),
        MAX_NEW_TOKENS,
    )


    # One Qwen generation at a time.
    async with qwen_semaphore:

        try:

            result = await run_in_threadpool(
                generate_qwen,
                req.prompt,
                req.system,
                max_new_tokens,
                req.temperature,
            )

            return {
                "model": "Qwen3-8B",
                "model_id": QWEN_MODEL,
                "response": result,
            }


        except torch.cuda.OutOfMemoryError:

            gc.collect()

            torch.cuda.empty_cache()

            raise HTTPException(
                status_code=503,
                detail=(
                    "GPU memory exhausted during Qwen generation."
                ),
            )


        except Exception as e:

            raise HTTPException(
                status_code=500,
                detail=str(e),
            )


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup_event():

    print()
    print("=" * 70)
    print("NullRoute AI SERVER READY")
    print("=" * 70)

    print(f"GPU       : {GPU_NAME}")
    print(f"Qwen      : {QWEN_MODEL}")
    print(f"DistilBERT: {DISTILBERT_MODEL}")
    print(f"MiniLM    : {MINILM_MODEL}")

    print(
        f"MiniLM dim: "
        f"{minilm_model.get_sentence_embedding_dimension()}"
    )

    print(
        f"VRAM      : "
        f"{torch.cuda.memory_allocated() / 1024**3:.2f} GB"
    )

    print("=" * 70)