FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WEB_HOST=127.0.0.1 \
    WEB_PORT=8081 \
    WEB_WORKERS=1 \
    WEB_LOG_LEVEL=INFO \
    ARCHANGEL_API_URL=http://127.0.0.1:8080 \
    ARCHANGEL_SESSION_DATABASE=/data/sessions.db \
    ARCHANGEL_WEB_LOG_PATH=/data/archangel-frontend.jsonl

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt \
    && addgroup --system --gid 10001 archangel \
    && adduser --system --uid 10001 --ingroup archangel archangel \
    && mkdir -p /data \
    && chmod 700 /data \
    && chown archangel:archangel /data

COPY --chown=archangel:archangel server.py healthcheck.py ./
COPY --chown=archangel:archangel webapp ./webapp
COPY --chown=archangel:archangel templates ./templates
COPY --chown=archangel:archangel static ./static

USER archangel
EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["python", "healthcheck.py"]

CMD ["sh", "-c", "exec gunicorn --bind $WEB_HOST:$WEB_PORT --workers $WEB_WORKERS --threads 4 server:app"]
