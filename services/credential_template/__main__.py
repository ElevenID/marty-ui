"""Entry point for credential-template service when run as python -m credential_template"""
from .main import app
import uvicorn
import os

if __name__ == "__main__":
    port = int(os.environ.get("SERVICE_PORT", 8003))
    uvicorn.run(app, host="0.0.0.0", port=port)
