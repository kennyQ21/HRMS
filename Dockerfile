FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    FLASK_ENV=production

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        poppler-utils \
        build-essential \
        libpq-dev \
        unixodbc-dev \
        libgomp1 \
        libglib2.0-0 \
        libgl1 \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Pre-download GLiNER model before requirements so this layer is never
# invalidated by requirements.txt changes
ARG HF_TOKEN=""
RUN pip install --no-cache-dir huggingface_hub && \
    python -c "import os; from huggingface_hub import snapshot_download; snapshot_download('urchade/gliner_mediumv2.1', token=os.getenv('HF_TOKEN') or None)"

COPY requirements.txt ./

# Install CPU-only torch first to avoid pulling in NVIDIA CUDA libraries (~2 GB)
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

RUN pip install --no-cache-dir -r requirements.txt

COPY . ./

EXPOSE 5000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000"]
