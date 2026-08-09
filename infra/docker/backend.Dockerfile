FROM python:3.11.9-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install --yes --no-install-recommends libcap2-bin libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 aegisflow \
    && useradd --system --uid 10001 --gid aegisflow --home-dir /app aegisflow

WORKDIR /app
COPY pyproject.toml README.md LICENSE alembic.ini ./
RUN python -m pip install --upgrade pip==25.1.1 \
    && python -m pip install torch==2.13.0 --index-url https://download.pytorch.org/whl/cpu \
    && python -m pip install hatchling==1.27.0 \
    && python -c "import subprocess,sys,tomllib; dependencies=tomllib.load(open('pyproject.toml','rb'))['project']['dependencies']; subprocess.check_call([sys.executable,'-m','pip','install',*dependencies])"
COPY apps/__init__.py ./apps/__init__.py
COPY apps/api ./apps/api
COPY packages ./packages
COPY services ./services
COPY training ./training
COPY scripts ./scripts
COPY migrations ./migrations
COPY docs/evaluation ./docs/evaluation
RUN python -m pip install --no-deps --no-build-isolation .
COPY models/registry ./models/registry

FROM runtime AS sensor-live
RUN setcap cap_net_raw=ep /usr/local/bin/python3.11
USER 10001:10001
CMD ["python", "-m", "services.sensor.main", "--mode", "live"]

FROM runtime AS backend
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
