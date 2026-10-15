FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WEB_HOST=127.0.0.1 \
    WEB_PORT=8081 \
    WEB_WORKERS=1 \
    ARCHANGEL_API_URL=http://127.0.0.1:8080 \
    ARCHANGEL_WEB_CONFIG=/data/web.json

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt \
    && addgroup --system --gid 10001 archangel \
    && adduser --system --uid 10001 --ingroup archangel archangel \
    && mkdir -p /data \
    && chown archangel:archangel /data

COPY --chown=archangel:archangel server.py ./server.py
COPY --chown=archangel:archangel templates ./templates
COPY --chown=archangel:archangel static ./static

USER archangel
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8081/', timeout=3)" || exit 1

CMD ["sh", "-c", "exec gunicorn --bind $WEB_HOST:$WEB_PORT --workers $WEB_WORKERS --threads 4 server:app"]
