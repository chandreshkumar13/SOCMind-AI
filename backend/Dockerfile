# Backend API image. Not built or run in the environment where it was written (Docker was not available there):
# treat it as untested until `docker compose build` has been run successfully.
FROM python:3.11-slim

# ENVIRONMENT=production: the API refuses to start with AUTH_MODE=disabled (app/core/auth.py). Supply AUTH_MODE=token and
# AUTH_TOKENS at run time, for example with --env-file. The image never contains a token.
ENV ENVIRONMENT=production PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# A dedicated, unprivileged user. /app/data holds the SQLite database: docker-compose.yml mounts a named volume there, and
# Docker gives a new named volume the ownership of the image directory it is mounted on, so it is created here, owned by socmind.
RUN useradd --create-home --uid 10001 socmind && chown socmind:socmind /app \
    && mkdir -p /app/data && chown socmind:socmind /app/data

COPY requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt

# Only the application code is copied: no tests, no .env files, no databases (see .dockerignore)
COPY app /app/app

USER socmind

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=4).status == 200 else 1)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
