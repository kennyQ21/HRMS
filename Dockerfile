FROM python:3.12-slim

WORKDIR /app 

ENV PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.7.1 \
    POETRY_VIRTUALENVS_CREATE=false \
    FLASK_APP=app.py \
    FLASK_ENV=production

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
    poppler-utils \
    bash \
    build-essential \
    libpq-dev \
    tesseract-ocr \
    libtesseract-dev \
    && apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/* \
    && pip install "poetry==$POETRY_VERSION" && poetry --version

COPY pyproject.toml poetry.lock* ./

RUN poetry install --no-root --no-dev && pip install flask-cors oracledb watchfiles

COPY . ./

EXPOSE 5000

# Run as non-root user for security
USER nobody

CMD ["poetry", "run", "gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
