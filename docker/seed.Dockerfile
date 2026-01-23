# syntax=docker/dockerfile:1
# Seed Service Dockerfile
# Runs demo data seeding script as a one-shot container
# Optimized with BuildKit cache mounts

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies with BuildKit cache
COPY requirements.txt* ./
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir \
    sqlalchemy[asyncio] \
    asyncpg \
    aiosqlite \
    httpx \
    fastapi \
    "pydantic[email]"

# Copy source code
COPY src/ ./src/
COPY scripts/ ./scripts/

# Set Python path
ENV PYTHONPATH=/app/src:/app

# Run seed script
CMD ["python", "scripts/seed_demo_data.py"]
