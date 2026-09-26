#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

mkdir -p "$ROOT/data"

PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH="$ROOT/node" \
"$ROOT/.venv/bin/python" \
  "$ROOT/node/stevens_public_testnet_node_v1_1.py" \
  --data-dir "$ROOT/data" \
  --genesis-file "$ROOT/node/testnet_genesis_v0_5_2.json" \
  --host 127.0.0.1 \
  --port 18801 \
  --public-url http://127.0.0.1:18801 \
  --peer http://142.93.158.54:18801 \
  --build-identity-file "$ROOT/node/build_identity.json"
