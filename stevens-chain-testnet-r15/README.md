# Stevens Chain Public Testnet — R15

Stevens Chain public testnet node package.

Network: `stevens-testnet-v0.5.2`
Consensus: `v0.5.2`
Security revision: `r15`
Sentinel: `v1.1`

**TEST TOKENS HAVE NO MONETARY VALUE.**

## Requirements

- Python 3.12 or newer
- Internet connection
- `cryptography==42.0.8`

## 1. Verify the package

From the package directory:

```bash
shasum -a 256 -c SHA256SUMS
```

Every packaged R15 file should report `OK`.

## 2. Create a Python environment

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

## 3. Start a local testnet node

```bash
mkdir -p data

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD/node" \
.venv/bin/python node/stevens_public_testnet_node_v1_1.py \
  --data-dir "$PWD/data" \
  --genesis-file "$PWD/node/testnet_genesis_v0_5_2.json" \
  --host 127.0.0.1 \
  --port 18801 \
  --public-url http://127.0.0.1:18801 \
  --peer http://142.93.158.54:18801 \
  --build-identity-file "$PWD/node/build_identity.json"
```

The initial public seed is:

`http://142.93.158.54:18801`

## 4. Check synchronization

In another terminal:

```bash
curl -s http://127.0.0.1:18801/status | python3 -m json.tool
```

Confirm:

- `network_id` is `stevens-testnet-v0.5.2`
- `peers` is at least 1
- `orphan_count` is 0 under normal synchronized operation
- height, tip, and cumulative work converge with the public network

## 5. Check release identity

```bash
curl -s http://127.0.0.1:18801/hello | python3 -m json.tool
```

The R15 core aggregate is:

`670bdb5af00672e2a69850814208e6c305674212e179142cd8b4f79e2ee469bb`

## Important

This is a public testnet release, not mainnet software.
Do not use testnet wallets, keys, credentials, recovery material, or tokens for production systems.
