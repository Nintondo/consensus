# Integration Roadmap

Goal: replicate the complete `libbitcoinconsensus` behavior in pure Rust while staying source-compatible with `rust-bitcoinconsensus`. Work proceeds in phases so we can ship incremental value and keep parity with Bitcoin Core.

---

## Phase 0 – Baseline & Scaffolding

1. **Publish API Surface – ✅ Done**  
   - Public API mirrors `rust-bitcoinconsensus` (`verify`, `verify_with_flags`, flags, error enum).  
   - Crate metadata + feature layout (`std`, `external-secp`) landed.  
   - Regression tests cover legacy spends to guard API surface.

2. **Transaction / UTXO Context – ✅ Done**  
   - `TransactionContext` enforces canonical encoding, index bounds, and precomputed hash cache.  
   - `SpentOutputs` validates pointers/amounts and blocks Taproot flag misuse.

3. **Testing Harness – ⏳ Planned**  
   - TODO: ingest Bitcoin Core JSON/script fixtures and run them under `cargo test`.  
   - TODO: add Core cross-check harness once interpreter stabilizes.

Exit criteria: ✅ achieved—the crate parses transactions, validates UTXO metadata, and runs today’s interpreter without panicking.

---

## Phase 1 – Script Interpreter Parity (Legacy & P2SH/Witness v0)

1. **Opcode Matrix – 🚧 In Progress**  
   - Stack/altstack infra plus rotation/tuck/drop ops implemented with depth checks, including the indexed family (`OP_PICK`, `OP_ROLL`, `OP_TUCK`, etc.) and `OP_CODESEPARATOR`.  
   - Numeric helpers, CLTV/CSV, and witness program scaffolding ported.  
   - Arithmetic opcodes now use a faithful ScriptNum parser so operands outside the 32-bit window (or violating MINIMALDATA) raise `ScriptError::Unknown` just like Core; unit tests cover the 2³¹ overflow regression (vector #722).  
   - Per-script limits (opcode budget, stack/altstack bounds, sigop-weighted CHECKMULTISIG accounting) now match Core, and regression tests lock in the `ScriptError::OpCount` path using CHECKSIG-heavy scripts. Next: prep execution data cache so future Taproot rules can reuse it.

2. **Flag Enforcement – 🚧 In Progress**  
   - `SIGPUSHONLY`, `MINIMALDATA`, `MINIMALIF`, `DISCOURAGE_UPGRADABLE_NOPS`, `CLEANSTACK`, and `NULLFAIL` are wired into the interpreter with targeted regression tests, and the helper bits now auto-toggle in the same combinations as Bitcoin Core (e.g., WITNESS ⇒ CLEANSTACK/MINIMALIF/NULLFAIL/P2SH/SIGPUSHONLY/WITNESS_PUBKEYTYPE).  
   - Newly added: Core’s `CheckSignatureEncoding` semantics (strict DER parsing when DERSIG/STRICTENC/LOW_S are set, low-S enforcement, segwit-only pubkey type enforcement) plus regression tests that cover non-DER malleations, high-S signatures, and uncompressed segwit pubkeys. Internally we now track the interpreter’s `ScriptError` the same way Core does (`Interpreter::last_script_error`), so future differential tests can assert on precise failure reasons even though the public API still reports the coarse `ERR_SCRIPT`.  
   - Fresh progress: `OP_RETURN`, the `*VERIFY` opcode family, and BIP65/BIP112 enforcement now emit Core’s specific `ScriptError`s (including `OpReturn`, `Verify`, `EqualVerify`, `CheckSigVerify`, `CheckMultiSigVerify`, `NumEqualVerify`, `NegativeLockTime`, and `UnsatisfiedLockTime`). Disabled and reserved opcodes are tagged as `DisabledOpcode`/`BadOpcode`, and the regression suite asserts on these diagnostics.  
   - Additional progress: script structural caps now match Core—the interpreter rejects scripts over 10 kB (`ScriptSize`), pushes over 520 bytes (`PushSize`), and scripts that execute more than 201 opcodes (`OpCount`). We now also track legacy + P2SH/Witness sigops exactly like Core so CHECKSIG/CHECKMULTISIG exhaustion is enforced, and regression tests cover the CHECKSIG-heavy worst case. Stack overflows now emit `StackSize`, and multisig argument validation reports `PubkeyCount`/`SigCount`. All of these conditions have regression tests that lock in the precise `ScriptError`.  
   - Witness programs now surface the right diagnostics (`WitnessProgramWrongLength`, `WitnessProgramWitnessEmpty`, `WitnessProgramMismatch`, `WitnessMalleated`, `WitnessMalleatedP2SH`, `WitnessUnexpected`, `WitnessPubkeyType`) and we fail fast when Taproot spends are requested (pending full Taproot implementation). SegWit-on-P2SH scriptSigs must now be canonical single pushes to match Core’s `WITNESS_MALLEATED_P2SH` rule.  
   - Remaining work: continue rounding out Taproot-only conditions and add Core fixture coverage for sigop accounting edge cases.
   - Latest fix: `CHECKMULTISIG` enforces `NULLFAIL` even when execution aborts early (e.g., leftover signature slots), so the BIP147 regression vectors (#1256) now raise `ScriptError::NullFail` exactly like Core.

3. **Signature Handling (ECDSA)**  
   - Honor `OP_CODESEPARATOR`, `SigVersion::BASE/WITNESS_V0`, and scriptCode modifications when hashing.  
   - DER parsing now supports Core’s “lax” mode for pre-BIP66 signatures, promotes strict encodings when the relevant flags activate, normalizes signatures before verification so high-S encodings stay valid when LOW_S is disabled, and strips the checked signature from `scriptCode` using a faithful `FindAndDelete` implementation.  
   - `CHECKSIGADD` and other Taproot-only opcodes remain gated until Phase 2 enables Schnorr. Sigop accounting is already at parity for legacy+SegWit, so the remaining focus here is keeping NULLFAIL regressions covered as we add any new opcode families.

4. **P2SH & Witness v0 Integration – 🚧 In Progress**  
   - scriptSig push-only enforcement, redeem-script execution, and basic P2WPKH/P2WSH paths exist.  
   - CLEANSTACK/default segwit flag plumbing partially present; sigop accounting + malleation rules still TODO.

Exit criteria: all Bitcoin Core script & transaction test vectors (legacy + SegWit v0) pass bit-for-bit.

---

## Phase 2 – Taproot / Tapscript Support

1. **Spent Output Plumbing**  
   - Require full previous-output set when Taproot flags are enabled.  
   - Extend `PrecomputedTransactionData` usage so Taproot signature hashing reuses cached values.

2. **Schnorr / BIP340 Verification**  
   - Integrate secp256k1 Schnorr verification (optionally via `external-secp`).  
   - Implement `SigVersion::TAPROOT` states and `CHECKSIG`, `CHECKSIGADD`, `CHECKMULTISIG` replacements per BIPs 341/342.

3. **Tapscript Interpreter Rules**  
   - Enforce Tapscript-specific limits (opcode budget, stack element caps, annex handling, leaf version rules).  
   - Validate control blocks, script tree paths, and tapleaf hashes exactly like Core.

4. **Cross-Compatibility Tests**  
   - Import Bitcoin Core Taproot test vectors; add custom regression tests for annex, key path, script path (including failures).  

Exit criteria: Taproot spends (key and script paths) verify identically to Core with and without P2SH wrapping.

---

## Phase 3 – Validation Hardening & Tooling

1. **Fuzzing & Differential Testing**  
   - Wire honggfuzz/AFL targets comparing our interpreter output to Core via RPC/FFI harness.  
   - Add random-script/property tests to catch edge cases.

2. **Performance / Memory Profiling**  
   - Benchmark against Core for representative workloads; optimize stack handling, sighash caching, and script parsing.  
   - Ensure `no_std` builds remain efficient (minimize allocations, use `alloc` wisely).

3. **Documentation & Maintenance**  
   - Produce detailed module docs (design rationale, deviations, safety notes).  
   - Outline release process, compatibility matrix, and integration tips for downstream crates.

Exit criteria: Robust CI (Linux/macOS/Windows, stable + MSRV), fuzzing gates, and documented guarantees matching `libbitcoinconsensus`.
