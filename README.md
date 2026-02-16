# consensus

Pure Rust implementation of Bitcoin's `bitcoinconsensus` verification surface (historically exposed as `libbitcoinconsensus`).

## Status

- Legacy, P2SH, SegWit v0, and Taproot/Tapscript validation are implemented.
- Differential checks against Bitcoin Core are available with the `core-diff` feature.
- Core vectors are vendored in `tests/data/`.
- Large script-assets corpus support is available via upstream minimizer artifacts.

## API

Main entrypoints in `src/lib.rs`:

- `verify`
- `verify_with_flags`
- `verify_with_details`
- `verify_with_flags_detailed`

## Feature Flags

- `std` (default)
- `external-secp` (implies `std`)
- `core-diff` (enables Core runtime differential tests/benchmarks)

## Quick Start

```bash
cargo test
```

```bash
cargo test --features core-diff
```

Fixture integrity check:

```bash
cargo test --test core_fixture_hashes
```

Core runtime differential (local Core checkout required):

```bash
BITCOIN_CORE_REPO=/path/to/bitcoin \
CORE_CPP_DIFF_BUILD_HELPER=1 \
cargo test --features core-diff --test core_cpp_runtime_diff -- --nocapture
```

Strict parity mode:

```bash
BITCOIN_CORE_REPO=/path/to/bitcoin \
CORE_CPP_DIFF_BUILD_HELPER=1 \
CORE_CPP_DIFF_REQUIRED=1 \
CORE_CPP_DIFF_STRICT=1 \
CORE_CPP_DIFF_ACCEPTED_SKIPS=noncanonical_flags,placeholder_vectors \
cargo test --features core-diff --test core_cpp_runtime_diff -- --nocapture
```

Script-assets parity profile:

```bash
SCRIPT_ASSETS_PARITY_PROFILE=1 \
SCRIPT_ASSETS_REQUIRE_UPSTREAM=1 \
SCRIPT_ASSETS_UPSTREAM_JSON=/path/to/script_assets_test.json \
SCRIPT_ASSETS_UPSTREAM_METADATA_JSON=/path/to/script_assets_test.metadata.json \
cargo test --test script_assets -- --nocapture
```

## Benchmarks

```bash
cargo bench --bench verification
```

```bash
cargo bench --bench verification --features core-diff
```

## Project Layout

- `src/lib.rs`: public API and verification flow
- `src/script.rs`: script interpreter
- `src/tx.rs`: transaction parsing and sighash helpers
- `tests/`: vectors, corpus checks, and differential suites

## Documentation

- `docs/integration-roadmap.md`: parity roadmap and findings
- `docs/github-ci.md`: CI and GitHub setup details

## Notes

- Taproot checksig/sighash paths require prevout context (`spent_outputs`).
- Under `VERIFY_TAPROOT`, non-taproot execution paths do not fail early when prevouts are absent.
- Amount semantics follow Core runtime: explicit `amount` is authoritative for checksig/sighash.
