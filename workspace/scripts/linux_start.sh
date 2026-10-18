#!/bin/sh
# Provided for reproduction; Linux execution was not verified.
set -eu
cd "$(dirname "$0")/.."
: "${SECRETRADAR_HMAC_KEY:?Supply at least 32 UTF-8 bytes independently}"
export PYTHONPYCACHEPREFIX="$PWD/.cache/pycache"
.venv/bin/python -m secretradar demo --db runtime/demo.db
exec .venv/bin/python -m secretradar serve --db runtime/demo.db --mode demo --port 8765
