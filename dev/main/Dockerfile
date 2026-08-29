# syntax=docker/dockerfile:1
# Cyense API — PRD v2.0 (dev/main)
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY baseline/ ./baseline/
COPY wordlists/ ./wordlists/

RUN useradd --create-home --shell /usr/sbin/nologin cyense \
    && mkdir -p /app/reports /app/brain \
    && chown -R cyense:cyense /app
USER cyense

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
