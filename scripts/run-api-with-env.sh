#!/bin/bash
# Wrapper script to run API with proper environment loading

set -e

cd "$(dirname "$0")/.."

# Activate venv
source .venv/bin/activate

# Load .env using Python (handles multi-line values properly)
if [ -f .env ]; then
    export $(python -c '
from dotenv import dotenv_values
config = dotenv_values(".env")
for key, value in config.items():
    if value:
        value = value.replace("\"", "\\\"")
        print(f"{key}=\"{value}\"")
' | xargs)
fi

# Change to src and run uvicorn
cd src
exec uvicorn oid4vc_api:app --reload --host 0.0.0.0 --port 8000
