FROM python:3.11.9-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --system --gid 10001 aegisflow \
    && useradd --system --uid 10001 --gid aegisflow --home-dir /app aegisflow

WORKDIR /app
COPY pyproject.toml README.md LICENSE alembic.ini ./
COPY apps/__init__.py ./apps/__init__.py
COPY apps/api ./apps/api
COPY packages ./packages
COPY services ./services
COPY training ./training
COPY scripts ./scripts
COPY migrations ./migrations
RUN python -m pip install --upgrade pip==25.1.1 \
    && python -m pip install .
COPY models/registry ./models/registry

USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
