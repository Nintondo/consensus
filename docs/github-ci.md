# GitHub CI Setup

This repository includes `.github/workflows/core-parity.yml`, which runs parity checks on pull requests and `main`.
The workflow installs Core helper build prerequisites via apt, including `libboost-dev` (required by current Bitcoin Core CMake configuration).

## Core Pinning

- The workflow pins Bitcoin Core from `tests/data/script_assets_generated_metadata.json` (`source_core_commit`).
- Current pinned commit: `4d7d5f6b79d4c11c47e7a828d81296918fd11d4d`.

## Upstream Script-Assets Input

Provide upstream script-assets in one of two ways.

1. Repository variables:
- `SCRIPT_ASSETS_UPSTREAM_JSON_URL`
- `SCRIPT_ASSETS_UPSTREAM_METADATA_URL`
- Optional secret for private URLs: `SCRIPT_ASSETS_UPSTREAM_AUTH_HEADER` (example: `Authorization: Bearer <token>`)

2. Committed files:
- `tests/data/script_assets_upstream.json`
- `tests/data/script_assets_upstream_metadata.json`

Required metadata keys:
- `source_core_commit`
- `source_generation`
- `artifact_case_count`
- `artifact_sha256`

## Generate Option B Artifacts

1. Produce `script_assets_test.json` from your local Bitcoin Core checkout (minimizer flow):
```bash
mkdir -p dump dump-min
for n in $(seq 1 10); do TEST_DUMP_DIR=dump test/functional/feature_taproot.py --dumptests; done
FUZZ=script_assets_test_minimizer ./bin/fuzz -merge=1 -use_value_profile=1 dump-min/ dump/
(echo -en '[\n'; cat dump-min/* | head -c -2; echo -en '\n]') > script_assets_test.json
```

2. Copy artifact into this repo:
```bash
cp /path/to/script_assets_test.json tests/data/script_assets_upstream.json
```

3. Generate metadata:
```bash
python3 scripts/generate_script_assets_upstream_metadata.py \
  --json tests/data/script_assets_upstream.json \
  --core-repo /path/to/bitcoin
```

4. Validate locally:
```bash
SCRIPT_ASSETS_PARITY_PROFILE=1 \
SCRIPT_ASSETS_REQUIRE_UPSTREAM=1 \
SCRIPT_ASSETS_UPSTREAM_JSON=tests/data/script_assets_upstream.json \
SCRIPT_ASSETS_UPSTREAM_METADATA_JSON=tests/data/script_assets_upstream_metadata.json \
cargo test --test script_assets -- --nocapture
```

## Branch Protection

- Require the `Core Parity` status check before merge.
