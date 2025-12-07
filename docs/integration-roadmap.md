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

3. **Testing Harness – 🚧 In Progress**  
   - Imported the latest `script_tests.json` straight from Bitcoin Core (including the Taproot-only vectors). The Rust harness now understands Core’s placeholder syntax (`#SCRIPT#`, `#CONTROLBLOCK#`, `#TAPROOTOUTPUT#`) and auto-builds the tapleaf/control-block/output key so the JSON stays identical to upstream.  
   - Taproot vector cases automatically feed the interpreter with synthetic `Utxo` entries so BIP341 signature hashing has the prevout context it expects, keeping us in lockstep with `VerifyScript`.  
   - TODO: add Core cross-check harness once interpreter stabilizes.

Exit criteria: ✅ achieved—the crate parses transactions, validates UTXO metadata, and runs today’s interpreter without panicking.

---

## Phase 1 – Script Interpreter Parity (Legacy & P2SH/Witness v0)

1. **Opcode Matrix – 🚧 In Progress**  
   - Stack/altstack infra plus rotation/tuck/drop ops implemented with depth checks, including the indexed family (`OP_PICK`, `OP_ROLL`, `OP_TUCK`, etc.) and `OP_CODESEPARATOR`.  
   - Numeric helpers, CLTV/CSV, and witness program scaffolding ported.  
   - Arithmetic opcodes now use a faithful ScriptNum parser so operands outside the 32-bit window (or violating MINIMALDATA) raise `ScriptError::Unknown` just like Core; unit tests cover the 2³¹ overflow regression (vector #722).  
   - Per-script limits (opcode budget, stack/altstack bounds, sigop-weighted CHECKMULTISIG accounting) now match Core, and regression tests lock in the `ScriptError::OpCount` path using CHECKSIG-heavy scripts. Execution data now caches code-separator positions, tapleaf hashes, annex bytes, and the tapscript validation-weight budget so the Schnorr paths can share the same bookkeeping Core relies on.

2. **Flag Enforcement – 🚧 In Progress**  
   - `SIGPUSHONLY`, `MINIMALDATA`, `MINIMALIF`, `DISCOURAGE_UPGRADABLE_NOPS`, `CLEANSTACK`, and `NULLFAIL` are wired into the interpreter with targeted regression tests, and the flag plumbing now mirrors Core (e.g., enabling WITNESS implicitly turns on `P2SH`, while the other helpers remain opt-in).  
   - Newly added: Core’s `CheckSignatureEncoding` semantics (strict DER parsing when DERSIG/STRICTENC/LOW_S are set, low-S enforcement, segwit-only pubkey type enforcement) plus regression tests that cover non-DER malleations, high-S signatures, and uncompressed segwit pubkeys. Internally we now track the interpreter’s `ScriptError` the same way Core does (`Interpreter::last_script_error`), so future differential tests can assert on precise failure reasons even though the public API still reports the coarse `ERR_SCRIPT`.  
   - Fresh progress: `OP_RETURN`, the `*VERIFY` opcode family, and BIP65/BIP112 enforcement now emit Core’s specific `ScriptError`s (including `OpReturn`, `Verify`, `EqualVerify`, `CheckSigVerify`, `CheckMultiSigVerify`, `NumEqualVerify`, `NegativeLockTime`, and `UnsatisfiedLockTime`). Disabled and reserved opcodes are tagged as `DisabledOpcode`/`BadOpcode`, and the regression suite asserts on these diagnostics.  
   - Additional progress: script structural caps now match Core—the interpreter rejects scripts over 10 kB (`ScriptSize`), pushes over 520 bytes (`PushSize`), and scripts that execute more than 201 opcodes (`OpCount`). We now also track legacy + P2SH/Witness sigops exactly like Core so CHECKSIG/CHECKMULTISIG exhaustion is enforced, and regression tests cover the CHECKSIG-heavy worst case. Stack overflows now emit `StackSize`, and multisig argument validation reports `PubkeyCount`/`SigCount`. All of these conditions have regression tests that lock in the precise `ScriptError`.  
   - Witness programs now surface the right diagnostics (`WitnessProgramWrongLength`, `WitnessProgramWitnessEmpty`, `WitnessProgramMismatch`, `WitnessMalleated`, `WitnessMalleatedP2SH`, `WitnessUnexpected`, `WitnessPubkeyType`) and we fail fast when Taproot spends are requested (pending full Taproot implementation). SegWit-on-P2SH scriptSigs must now be canonical single pushes to match Core’s `WITNESS_MALLEATED_P2SH` rule.  
   - Remaining work: continue rounding out Taproot-only conditions and add Core fixture coverage for sigop accounting edge cases.
   - Latest fixes: `CHECKMULTISIG` enforces `NULLFAIL` even when execution aborts early (e.g., leftover signature slots), so the BIP147 regression vectors (#1256) now raise `ScriptError::NullFail` exactly like Core. A dedicated regression test exercises the “`CHECKMULTISIG NOT` hides failure” pattern to keep this behavior locked in.  
   - WITNESS/TAPROOT flag normalization mirrors Core—requesting WITNESS automatically toggles `P2SH`, and TAPROOT implies WITNESS as well (triggering the same `P2SH` requirement) plus its own spent-output requirement. Regression tests cover the normalization matrix.  
   - New: when callers supply prevouts (`SpentOutputs`), the verifier now cross-checks the scriptPubKey and derives the satoshi amount directly from the provided UTXO, so SegWit spends no longer need to duplicate the amount alongside the prevout set. TAPROOT verification continues to error unless prevouts are provided. Regression tests cover both behaviors, and `PrecomputedTransactionData` now caches the BIP341 single hashes (amounts/scripts) when Taproot prevouts are present so later Taproot sighash logic can reuse them.

3. **Signature Handling (ECDSA)**  
   - Honor `OP_CODESEPARATOR`, `SigVersion::BASE/WITNESS_V0`, and scriptCode modifications when hashing.  
   - DER parsing now supports Core’s “lax” mode for pre-BIP66 signatures, promotes strict encodings when the relevant flags activate, normalizes signatures before verification so high-S encodings stay valid when LOW_S is disabled, and strips the checked signature from `scriptCode` using a faithful `FindAndDelete` implementation.  
   - Sigop accounting is already at parity for legacy+SegWit, and the regression suite exercises the NULLFAIL corner-cases so future opcode work cannot accidentally reintroduce the BIP147 bypasses.

4. **P2SH & Witness v0 Integration – 🚧 In Progress**  
   - scriptSig push-only enforcement, redeem-script execution, and basic P2WPKH/P2WSH paths exist.  
   - CLEANSTACK/default segwit flag plumbing partially present; sigop accounting + malleation rules still TODO.

Exit criteria: all Bitcoin Core script & transaction test vectors (legacy + SegWit v0) pass bit-for-bit.

---

## Phase 2 – Taproot / Tapscript Support

1. **Spent Output Plumbing**  
   - Require full previous-output set when Taproot flags are enabled.  
   - Extend `PrecomputedTransactionData` usage so Taproot signature hashing reuses cached values.
   - Taproot witness parser now mirrors Core: annex (if present) is hashed for future sighashes, control blocks are validated (length/modulo 32) and mapped back to tapleaf hashes, and the tweaked key commitment is recomputed in Rust so script-path spends execute under `SigVersion::Taproot`. The `VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION` policy flag is wired up, and tests cover annex handling, malformed control blocks, empty witnesses, and future leaf versions.

2. **Schnorr / BIP340 Verification**  
   - Integrate secp256k1 Schnorr verification (optionally via `external-secp`).  
   - Script-path spending now enforces BIP340 signature sizes, sighash-type rules (implicit `SIGHASH_DEFAULT`, explicit encodings must be non-zero), tapleaf hashing, previous-output lookups, and the tapscript validation-weight decrement that Core uses to cap the SIGOPs/weight ratio. Key-path spends reuse the same helper and validate the tweaked output key in pure Rust. Regression tests cover happy-path key/script signatures, NULLFAIL staying disabled for tapscript, and the discouragement flag for future pubkey encodings.
   - Remaining work: lift the `VERIFY_TAPROOT` guard on Schnorr verification when `external-secp` is enabled, and implement the tapscript variants of `CHECKMULTISIG`/`CHECKMULTISIGVERIFY`.

3. **Tapscript Interpreter Rules**  
   - Enforce Tapscript-specific limits (opcode budget, stack element caps, annex handling, leaf version rules).  
   - Validate control blocks, script tree paths, and tapleaf hashes exactly like Core.
   - `OP_CHECKSIGADD` now behaves exactly like Core: it is only available under `SigVersion::Taproot`, performs Schnorr verification (including validation-weight charging), adds the result to the existing accumulator, and never triggers `NULLFAIL` even when the signature is non-empty. New integration tests cover both the satisfied and unsatisfied branches so stack ordering and arithmetic remain locked in.  
   - `OP_CHECKMULTISIG`/`OP_CHECKMULTISIGVERIFY` are now rejected inside tapscript (`SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG`), and the interpreter scans scripts for the OP_SUCCESS ranges before execution. Unknown OP_SUCCESS opcodes short-circuit to success unless the new `VERIFY_DISCOURAGE_OP_SUCCESS` flag is set, which surfaces `ScriptError::DiscourageOpSuccess` just like Core. Tests cover both the soft-success case and the policy failure. Because Core hasn’t assigned any new semantics to those OP_SUCCESS slots yet, multisig policies are expected to be written using `OP_CHECKSIGADD` loops, so there’s nothing else to port until a future BIP activates.  
   - Added an integration test that mirrors Core’s recommended `multi_a` tapscript multisig: we embed three x-only pubkeys inside the script, loop through `OP_CHECKSIG`/`OP_CHECKSIGADD`, and compare the accumulator against the desired threshold via `OP_NUMEQUAL`. The test signs two of the three slots (plus a negative case) so we validate both success and failure paths in pure Rust and prove our stack ordering matches the descriptor tooling.  
   - Documented the OP_SUCCESS opcode ranges inline (citing Bitcoin Core’s `src/script/script.cpp:IsOpSuccess` from `~/dev/bitcoin/bitcoin`) so future opcode assignments have a single source of truth inside the interpreter.  
   - MINIMALIF enforcement no longer depends on the policy flag when executing tapscript: every `OP_IF/OP_NOTIF` branch now insists on minimal encodings per BIP342, and the regression suite exercises the error path so future refactors can’t regress this implicit rule.
   - Script arithmetic continues to use the legacy 4-byte `ScriptNum` window even under tapscript, matching Core’s current consensus rules (BIP342 leaves room for future 64-bit expansion, but Bitcoin Core v26.x still enforces the 32-bit limit). A callout in the interpreter docs highlights this so contributors don’t accidentally widen the range ahead of upstream.
   - Legacy sigop accounting remains unchanged for Taproot spends—Bitcoin Core’s `WitnessSigOps()` helper currently returns `0` for v1 programs and relies entirely on the tapscript validation-weight budget to cap signature checks—so our interpreter mirrors that behaviour. Any future change would have to land upstream first.

4. **Cross-Compatibility Tests**  
   - Import Bitcoin Core Taproot test vectors; add custom regression tests for annex, key path, script path (including failures).  
   - Added bespoke coverage for tapscript Schnorr verification (valid/invalid signatures, `CHECKSIGADD` arithmetic, pubkey-type discouragement) so future refactors can be validated without waiting on the upstream vector suite.

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
