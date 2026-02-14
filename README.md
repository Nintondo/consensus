# consensus

Pure Rust implementation of Bitcoin's `libbitcoinconsensus` verification surface.

This crate aims to stay source-compatible with `rust-bitcoinconsensus` while keeping the core script engine and transaction checks in Rust.

## Current Status

- Active development.
- Legacy, P2SH, SegWit v0, and Taproot/Tapscript paths are implemented.
- Recent Core-parity updates include:
  - tapscript validation-weight charging for non-empty signatures (including upgradable pubkey types),
  - BIP341 applicability gate for v1 witness programs (`version=1`, `program_len=32`, non-P2SH),
  - pay-to-anchor carveout handling (`OP_1 0x024e73`) aligned with Core,
  - tapscript-specific MINIMALIF diagnostic mapping,
  - tapscript behavior that does not inherit legacy 10,000-byte script-size or 201-opcode limits.
- Full parity work is tracked in `docs/integration-roadmap.md`.
- `CONSENSUS_VERSION` is currently a placeholder (`0`).

## What This Repository Provides

- Public verification APIs in `src/lib.rs`:
  - `verify`
  - `verify_with_flags`
  - `verify_with_details`
  - `verify_with_flags_detailed`
- Script verification flags matching `libbitcoinconsensus`.
- Error codes (`Error`) plus detailed interpreter failures (`ScriptError`).
- Optional differential testing against `libbitcoinconsensus` through the `core-diff` feature.

## Feature Flags

- `std` (default): std-backed build.
- `external-secp`: use upstream global `secp256k1` verification context (implies `std`).
- `core-diff`: enable differential tests/benchmarks using `bitcoinconsensus`.

## Repository Map (Agent-Oriented)

- `src/lib.rs`: public API, flags, top-level verification flow.
- `src/script.rs`: script interpreter and opcode/flag enforcement.
- `src/tx.rs`: transaction parsing, prevout handling, precomputed sighash data.
- `src/types.rs`: C-like integer aliases used in public types.
- `tests/script_vectors.rs`: Bitcoin Core-style script vector harness (`tests/data/script_tests.json`).
- `tests/random_consistency.rs`: property-based differential checks (`core-diff`).
- `benches/verification.rs`: Criterion benchmarks for representative spend types.
- `docs/integration-roadmap.md`: parity plan and implementation status.

## Quick Start

```bash
cargo test
```

Run differential tests (this crate vs `libbitcoinconsensus`):

```bash
cargo test --features core-diff
```

Run benchmarks:

```bash
cargo bench --bench verification
```

## API Notes

- `verify` and `verify_with_details` choose default flags based on whether `spent_outputs` are provided.
- Taproot verification requires previous outputs (`spent_outputs`), and verification returns `ERR_SPENT_OUTPUTS_REQUIRED` when missing.
- When `spent_outputs` are provided, the verifier cross-checks the current input scriptPubKey and derives the amount from the matched prevout.
- Witness v1 dispatch follows Core’s Taproot applicability rules and pay-to-anchor carveout behavior.

## Minimal Usage Example

```rust
use consensus::{verify_with_flags, VERIFY_P2SH, VERIFY_WITNESS};

fn verify_input(
    spent_script_pubkey: &[u8],
    amount_sat: u64,
    spending_tx_bytes: &[u8],
) -> Result<(), consensus::Error> {
    let flags = VERIFY_P2SH | VERIFY_WITNESS;
    verify_with_flags(
        spent_script_pubkey,
        amount_sat,
        spending_tx_bytes,
        None, // use Some(&[Utxo]) for Taproot or explicit prevout context
        0,
        flags,
    )
}
```

## Contributor / Agent Checklist

- Keep public behavior aligned with `rust-bitcoinconsensus` API semantics.
- Add or update tests when changing opcode behavior or flag handling.
- Prefer vector and differential coverage (`tests/script_vectors.rs`, `core-diff`) for consensus-sensitive changes.
- Update `docs/integration-roadmap.md` when parity milestones move.
