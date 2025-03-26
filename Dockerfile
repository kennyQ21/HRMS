FROM python:3.12-slim

WORKDIR /app 

ENV PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.7.1 \
    POETRY_VIRTUALENVS_CREATE=false \
    FLASK_APP=app.py \
    FLASK_ENV=development

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

RUN poetry install --no-root && pip install flask-cors oracledb watchfiles 

COPY . ./

EXPOSE 5000

CMD ["poetry", "run", "flask", "run", "--host=0.0.0.0", "--port=5000", "--reload"]
