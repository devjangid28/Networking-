# NetProof - neutral network-change validation server
#
# Build:     docker build -t netproof .
# Run:       docker compose up -d   (or see docker-compose.yml)
# Data:      SQLite lives in the NETPROOF_DB path (defaults to /app/backend/data).
#            Mount a volume there to survive container rebuilds.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend backend
COPY web web

# Run as an unprivileged user, never root. The data dir is chowned so the
# writable SQLite store lives under the netproof user; code/site-packages
# stay root-owned and read-only (best practice for a web process).
RUN useradd --no-log-init --create-home --uid 10001 --shell /usr/sbin/nologin netproof \
    && mkdir -p /app/backend/data \
    && chown -R netproof:netproof /app/backend /app/web
USER netproof

WORKDIR /app/backend

ENV NETPROOF_HOST=0.0.0.0 \
    NETPROOF_PORT=8000

# Security: the admin password MUST be supplied at deploy time.
#   -e NETPROOF_ADMIN_USER=admin -e NETPROOF_ADMIN_PASS=<strong-secret>
# Reject accidental default-credential startups.
ENV NETPROOF_ADMIN_USER=admin \
    NETPROOF_ADMIN_PASS=""

EXPOSE 8000

VOLUME ["/app/backend/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status==200 else 1)"

CMD ["sh", "-c", "test -n \"$NETPROOF_ADMIN_PASS\" || { echo 'NETPROOF_ADMIN_PASS is required (set it in docker-compose.yml/.env)'; exit 1; }; python -m uvicorn main:app --host 0.0.0.0 --port 8000"]