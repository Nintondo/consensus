# consensus

Pure Rust implementation of Bitcoin's `libbitcoinconsensus` verification surface.

## Status

- Legacy, P2SH, SegWit v0, and Taproot/Tapscript verification paths are implemented.
- Differential testing against `libbitcoinconsensus` is available behind `core-diff`.
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
- `core-diff` (enables `bitcoinconsensus` differential tests/benchmarks)

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
