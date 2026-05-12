# Canvas Credentials Test Sandbox
# Lightweight Python/FastAPI service that simulates Canvas LMS LTI 1.3 endpoints.
FROM python:3.12-slim

WORKDIR /app

COPY marty-ui/docker/canvas-sandbox/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY marty-ui/docker/canvas-sandbox/main.py .

EXPOSE 8017

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8017/health')" || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8017", "--log-level", "info"]
