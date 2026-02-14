# consensus

Pure Rust implementation of Bitcoin's `libbitcoinconsensus` verification surface.

## Status

- Legacy, P2SH, SegWit v0, and Taproot/Tapscript verification paths are implemented.
- Differential testing against Bitcoin Core runtime surfaces is available behind `core-diff`.
- Core vector suites are vendored in-tree and exercised by tests.

## Features

- API compatible surface in `src/lib.rs`:
  - `verify`
  - `verify_with_flags`
  - `verify_with_details`
  - `verify_with_flags_detailed`
- Script flags and error codes aligned with `libbitcoinconsensus` semantics.
- Core-parity coverage through script vectors, tx corpus replay, sighash vectors, BIP341 wallet vectors, and randomized differential tests.

## Feature Flags

- `std` (default)
- `external-secp` (implies `std`)
- `core-diff` (enables Core differential tests/benchmarks)

## Quick Start

```bash
cargo test
```

```bash
cargo test --features core-diff
```

```bash
cargo test --test core_fixture_hashes
```

If you want fixture source checks against your local Bitcoin Core checkout:

```bash
BITCOIN_CORE_REPO=/path/to/bitcoin cargo test --test core_fixture_hashes
```

Direct C++ runtime differential harness for current Core (v28+):

```bash
BITCOIN_CORE_REPO=/path/to/bitcoin \
CORE_CPP_DIFF_BUILD_HELPER=1 \
cargo test --features core-diff --test core_cpp_runtime_diff -- --nocapture
```

Or prebuild once and point directly at the helper binary:

```bash
cmake -S tests/core_cpp_helper -B /tmp/core_cpp_helper -DBITCOIN_CORE_REPO=/path/to/bitcoin
cmake --build /tmp/core_cpp_helper --target core_consensus_helper -j4
CORE_CPP_DIFF_HELPER_BIN=/tmp/core_cpp_helper/core_consensus_helper \
cargo test --features core-diff --test core_cpp_runtime_diff -- --nocapture
```

Parity-audit mode (fail if backend is missing and fail on unaccepted skips):

```bash
BITCOIN_CORE_REPO=/path/to/bitcoin \
CORE_CPP_DIFF_BUILD_HELPER=1 \
CORE_CPP_DIFF_REQUIRED=1 \
CORE_CPP_DIFF_STRICT=1 \
CORE_CPP_DIFF_ACCEPTED_SKIPS=unsupported_flags \
cargo test --features core-diff --test core_cpp_runtime_diff -- --nocapture
```

## Benchmarks

```bash
cargo bench --bench verification
```

```bash
cargo bench --bench verification --features core-diff
```

## Repository Map

- `src/lib.rs`: public API and top-level verification flow
- `src/script.rs`: script interpreter and opcode/flag rules
- `src/tx.rs`: transaction parsing and sighash precompute helpers
- `tests/`: vector, corpus, and differential parity suites
- `docs/integration-roadmap.md`: parity roadmap and audit backlog

## Notes

- Taproot verification requires prevout context (`spent_outputs`).
- `CONSENSUS_VERSION` is currently a placeholder (`0`).
