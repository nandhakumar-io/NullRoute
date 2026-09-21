FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev curl nmap \
    && rm -rf /var/lib/apt/lists/*

# Build context is the repo root (see docker-compose.yml), so paths are
# relative to the project root, not this backend/ directory.
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Optional ML stack (DistilBERT fine-tuning + inference). Off by default to keep
# the API image small; the training-worker service builds with INSTALL_ML=true.
# Set the same arg on the backend build if you want the API itself to serve a
# promoted DistilBERT model (otherwise it falls back to the configured classifier).
ARG INSTALL_ML=false
COPY backend/requirements-ml.txt .
RUN if [ "$INSTALL_ML" = "true" ]; then \
      pip install --no-cache-dir --extra-index-url https://download.pytorch.org/whl/cpu -r requirements-ml.txt; \
    fi

COPY backend/ .
COPY sample_configs /app/sample_configs
COPY policies /app/policies

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]