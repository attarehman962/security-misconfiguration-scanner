# Dockerfile

FROM python:3.11-slim AS base

# Prevent Python from writing .pyc files and buffering stdout (clean container logs)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system deps needed by some Python packages (psycopg2, etc.)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first — this layer is cached unless requirements.txt changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Now copy the application source
COPY . .

# Create a non-root user and give it ownership of the app directory
RUN groupadd --gid 1000 appgroup \
    && useradd --uid 1000 --gid appgroup --shell /bin/bash --create-home appuser \
    && chown -R appuser:appgroup /app

USER appuser

# Healthcheck hits the FastAPI /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]




# Dockerfile.playwright
FROM mcr.microsoft.com/playwright/python:v1.45.0-jammy

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN groupadd --gid 1000 scraperuser \
    && useradd --uid 1000 --gid scraperuser --create-home scraperuser \
    && chown -R scraperuser:scraperuser /app

USER scraperuser

CMD ["python", "-m", "app.scraper.run"]