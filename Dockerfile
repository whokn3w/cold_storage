FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=UTC

RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY app.py /app/app.py
COPY inventory.py /app/inventory.py
COPY indicators.py /app/indicators.py
COPY failure_records.py /app/failure_records.py
COPY history_sync.py /app/history_sync.py
COPY history_sync_cli.py /app/history_sync_cli.py
COPY catalog_refresh_cli.py /app/catalog_refresh_cli.py
COPY assets /app/assets

USER 1000:1000

EXPOSE 8080

CMD ["python", "/app/app.py"]
