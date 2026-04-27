FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    FLASK_ENV=production

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        poppler-utils \
        build-essential \
        libpq-dev \
        libgl1 \
        libglib2.0-0 \
        libgomp1 \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

# Pre-download EasyOCR models (craft detection + english recognition, ~150 MB total)
# so the first OCR request doesn't trigger a runtime download that can OOM-kill the worker.
RUN python -c "import easyocr; easyocr.Reader(['en'], gpu=False, verbose=False)"

COPY . ./

EXPOSE 5000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000"]
