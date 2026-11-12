# syntax=docker/dockerfile:1
# One image: Django static files (admin) are collected at build time and served by whitenoise.
# Production linux/arm64 images are built and published by GitHub Actions; Jenkins deployment only pulls them. Also builds on x86 for local checks.

# mysqlclient has no Linux wheel: build it against the MariaDB Connector/C headers in a builder
# stage, and ship only the shared library (libmariadb3) in the runtime image.
FROM python:3.14-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.12.9 /uv /usr/local/bin/uv
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential pkg-config default-libmysqlclient-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app/backend
COPY backend/pyproject.toml backend/uv.lock backend/.python-version ./
RUN uv sync --frozen --no-dev --no-install-project

FROM python:3.14-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends libmariadb3 \
 && rm -rf /var/lib/apt/lists/*
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
COPY --from=build /opt/venv /opt/venv
WORKDIR /app/backend
COPY backend/ ./
RUN DJANGO_SECRET_KEY=collectstatic-only SIGNING_KEY_ENCRYPTION_KEY=collectstatic-only python manage.py collectstatic --noinput \
 && useradd --uid 1000 --no-create-home app
USER app
EXPOSE 8000
CMD ["sh", "-c", "exec gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers ${GUNICORN_WORKERS:-2} --timeout 30 --access-logfile -"]
