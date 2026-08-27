# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# Dependencies first for layer caching.
COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install ".[dev]"

COPY . .
RUN pip install -e ".[dev]"

EXPOSE 8000
# Dev default; prod compose overrides with gunicorn (M5).
CMD ["flask", "--app", "keystone_api:create_app", "run", "--host", "0.0.0.0", "--port", "8000", "--debug"]

# --- production image: gunicorn + gevent (WebSocket-capable) ---
FROM base AS prod
RUN pip install -e ".[prod]"
ENV KEYSTONE_ENV=production
EXPOSE 8000
CMD ["gunicorn", "-k", "gevent", "-w", "4", "-b", "0.0.0.0:8000", \
     "--access-logfile", "-", "--error-logfile", "-", "keystone_api:create_app()"]
