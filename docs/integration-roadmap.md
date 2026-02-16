# Integration Roadmap

Goal: replicate the complete `libbitcoinconsensus` behavior in pure Rust while staying source-compatible with `rust-bitcoinconsensus`. Work proceeds in phases so we can ship incremental value and keep parity with Bitcoin Core.

Current state snapshot (February 15, 2026):
- Phases 0 through 6 are completed for the current parity scope.
- No known open consensus/runtime parity mismatches remain against the pinned Core reference used by this repo.
- Remaining work is ongoing maintenance for future upstream Core changes and corpus refresh cadence.

---

## Phase 0 – Baseline & Scaffolding ✅ Completed

1. **Publish API Surface – ✅ Done**  
   - Public API mirrors `rust-bitcoinconsensus` (`verify`, `verify_with_flags`, flags, error enum).  
   - Crate metadata + feature layout (`std`, `external-secp`) landed.  
   - Regression tests cover legacy spends to guard API surface.

2. **Transaction / UTXO Context – ✅ Done**  
  - `TransactionContext` enforces canonical encoding/index bounds and provides precomputed-hash builders consumed by the interpreter.  
  - `SpentOutputs` validates pointers/amounts and blocks Taproot flag misuse.
   - BIP143 cache fields now use exact double-SHA commitments over serialized prevouts/sequences/outputs (matching Core’s precompute objects).

3. **Testing Harness – ✅ Done**  
  - Imported the latest `script_tests.json` straight from Bitcoin Core (including the Taproot-only vectors). The Rust harness now understands Core’s placeholder syntax (`#SCRIPT#`, `#CONTROLBLOCK#`, `#TAPROOTOUTPUT#`) and auto-builds the tapleaf/control-block/output key so the JSON stays identical to upstream.  
  - Taproot vector cases automatically feed the interpreter with synthetic `Utxo` entries so BIP341 signature hashing has the prevout context it expects, keeping us in lockstep with `VerifyScript`.  
   - Added focused parity guardrails: `CHECKLOCKTIMEVERIFY` flag token parsing in the script-vector harness, in-repo script-assets subset/superset checks (`tests/script_assets.rs` + `tests/data/script_assets_test.json`) augmented with Core tx-corpus large-corpus checks, plus imported Core data suites for `sighash.json`, `tx_valid.json`, `tx_invalid.json`, and `bip341_wallet_vectors.json`.
   - Fixture integrity gate added: `tests/core_fixture_hashes.rs` pins SHA256 hashes for vendored Core JSON files and, when `BITCOIN_CORE_REPO` points to a local Core checkout, asserts byte-for-byte parity with upstream source files.
   - Upstream corpus automation is wired in CI for parity profiles; fixture refresh remains an explicit/pinned update step with integrity checks.

Exit criteria: ✅ achieved—the crate parses transactions, validates UTXO metadata, and runs today’s interpreter without panicking.

---

## Phase 1 – Script Interpreter Parity (Legacy & P2SH/Witness v0) ✅ Completed

1. **Opcode Matrix – ✅ Done (for current Core semantics)**  
   - Stack/altstack infra plus rotation/tuck/drop ops implemented with depth checks, including the indexed family (`OP_PICK`, `OP_ROLL`, `OP_TUCK`, etc.) and `OP_CODESEPARATOR`.  
   - Numeric helpers, CLTV/CSV, and witness program scaffolding ported.  
   - Arithmetic opcodes now use a faithful ScriptNum parser so operands outside the 32-bit window (or violating MINIMALDATA) raise `ScriptError::Unknown` just like Core; unit tests cover the 2³¹ overflow regression (vector #722).  
   - Per-script limits (opcode budget, stack/altstack bounds, sigop-weighted CHECKMULTISIG accounting) now match Core, and regression tests lock in the `ScriptError::OpCount` path using CHECKSIG-heavy scripts. Execution data now caches code-separator positions, tapleaf hashes, annex bytes, and the tapscript validation-weight budget so the Schnorr paths can share the same bookkeeping Core relies on.

2. **Flag Enforcement – ✅ Done**  
   - `SIGPUSHONLY`, `MINIMALDATA`, `MINIMALIF`, `DISCOURAGE_UPGRADABLE_NOPS`, `CLEANSTACK`, and `NULLFAIL` are wired into the interpreter with targeted regression tests, and flag handling now mirrors Core/libbitcoinconsensus passthrough semantics (supported-bit validation only, no implicit bit promotion for non-canonical combinations).  
   - Newly added: Core’s `CheckSignatureEncoding` semantics (strict DER parsing when DERSIG/STRICTENC/LOW_S are set, low-S enforcement, segwit-only pubkey type enforcement) plus regression tests that cover non-DER malleations, high-S signatures, and uncompressed segwit pubkeys. Internally we now track the interpreter’s `ScriptError` the same way Core does (`Interpreter::last_script_error`), so future differential tests can assert on precise failure reasons even though the public API still reports the coarse `ERR_SCRIPT`.  
   - Fresh progress: `OP_RETURN`, the `*VERIFY` opcode family, and BIP65/BIP112 enforcement now emit Core’s specific `ScriptError`s (including `OpReturn`, `Verify`, `EqualVerify`, `CheckSigVerify`, `CheckMultiSigVerify`, `NumEqualVerify`, `NegativeLockTime`, and `UnsatisfiedLockTime`). Disabled and reserved opcodes are tagged as `DisabledOpcode`/`BadOpcode`, and the regression suite asserts on these diagnostics.  
   - Additional progress: script structural caps now match Core for legacy + Witness v0 paths—the interpreter rejects scripts over 10 kB (`ScriptSize`), pushes over 520 bytes (`PushSize`), and scripts that execute more than 201 opcodes (`OpCount`) where Core enforces those limits. Tapscript keeps Core’s distinct behavior (stack/push limits still enforced, but no legacy 10 kB / 201-opcount gate). We also track legacy + P2SH/Witness sigops exactly like Core so CHECKSIG/CHECKMULTISIG exhaustion is enforced, and regression tests cover the CHECKSIG-heavy worst case. Stack overflows now emit `StackSize`, and multisig argument validation reports `PubkeyCount`/`SigCount`. All of these conditions have regression tests that lock in the precise `ScriptError`.  
   - Latest parity fix: `SCRIPT_VERIFY_CONST_SCRIPTCODE` is now supported end-to-end, including legacy `OP_CODESEPARATOR` rejection and `SIG_FINDANDDELETE` rejection behavior (`OP_CODESEPARATOR` and `SIG_FINDANDDELETE` script errors), with vector-harness mappings aligned to Core’s names.
   - Witness programs now surface the right diagnostics (`WitnessProgramWrongLength`, `WitnessProgramWitnessEmpty`, `WitnessProgramMismatch`, `WitnessMalleated`, `WitnessMalleatedP2SH`, `WitnessUnexpected`, `WitnessPubkeyType`), and SegWit-on-P2SH scriptSigs must be canonical single pushes to match Core’s `WITNESS_MALLEATED_P2SH` rule.  
   - Upstream note: Bitcoin Core still rejects tapscript `CHECKMULTISIG(VERIFY)` (`SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG`), so parity for current Core behavior is to reject those opcodes as implemented here.
   - Latest fixes: `CHECKMULTISIG` enforces `NULLFAIL` even when execution aborts early (e.g., leftover signature slots), so the BIP147 regression vectors (#1256) now raise `ScriptError::NullFail` exactly like Core. A dedicated regression test exercises the “`CHECKMULTISIG NOT` hides failure” pattern to keep this behavior locked in.  
   - Latest parity fix: `CHECKMULTISIG` no longer raises `NULLFAIL` on intermediate pubkey mismatches while signature matching is still in progress; `NULLFAIL` is now applied only on final failure, matching Core’s `EvalScript` cleanup path.  
   - Latest parity fix: flag semantics now match Core’s API entrypoint behavior for non-canonical combinations (`VERIFY_TAPROOT`-only / `VERIFY_WITNESS`-only): bits are passed through unchanged after supported-bit validation. Regression tests pin both combinations and include differential coverage against `libbitcoinconsensus`.
   - New: when callers supply prevouts (`SpentOutputs`), the verifier now cross-checks the scriptPubKey and derives the satoshi amount directly from the provided UTXO, so SegWit spends no longer need to duplicate the amount alongside the prevout set. TAPROOT verification continues to error unless prevouts are provided. Regression tests cover both behaviors, and `PrecomputedTransactionData` now caches the BIP341 single hashes (amounts/scripts) when Taproot prevouts are present so later Taproot sighash logic can reuse them.

3. **Signature Handling (ECDSA)**  
  - Honor `OP_CODESEPARATOR`, `SigVersion::BASE/WITNESS_V0`, and scriptCode modifications when hashing.  
  - DER parsing now supports Core’s “lax” mode for pre-BIP66 signatures, promotes strict encodings when the relevant flags activate, normalizes signatures before verification so high-S encodings stay valid when LOW_S is disabled, and strips the checked signature from `scriptCode` using a faithful opcode-boundary-aware `FindAndDelete` implementation.  
  - Sigop accounting is already at parity for legacy+SegWit, and the regression suite exercises the NULLFAIL corner-cases so future opcode work cannot accidentally reintroduce the BIP147 bypasses.
  - Latest parity fix: pre-tapscript `CONST_SCRIPTCODE` checksig/checkmultisig paths now follow Core’s error precedence by applying legacy `FindAndDelete` checks before signature/pubkey encoding checks. Targeted regressions pin these classifications.
   - Latest parity fix: `CHECKSEQUENCEVERIFY` now mirrors Core’s `CheckSequence` semantics by enforcing `tx.version >= 2` and comparing masked sequence values (instead of rejecting script operands above `u32::MAX`).
   - Latest parity fix: CSV version gating now uses Core’s current unsigned transaction-version semantics (`uint32_t`), so negative serialized versions (e.g. `0xffffffff`) are treated as large versions and pass the `>= 2` gate.
   - Latest parity fix: witness-v0 checksig/checkmultisig now preserve `OP_CODESEPARATOR` bytes in scriptCode (legacy-only stripping), while legacy paths still strip as required.
   - Latest parity fix: witness-v0 sighash now commits the raw hashtype byte exactly like Core (no enum normalization before BIP143 encoding), including non-standard hashtype values.
   - Latest parity fix: `STRICTENC` hashtype validation now masks only `SIGHASH_ANYONECANPAY` (Core’s `IsDefinedHashtypeSignature` behavior), not all high bits.

4. **P2SH & Witness v0 Integration – ✅ Done**  
   - scriptSig push-only enforcement, redeem-script execution, and P2WPKH/P2WSH validation all mirror Bitcoin Core, including the canonical redeem push requirement for P2SH-witness spends.  
   - Verify flow order now matches Core: post-`scriptPubKey` `EvalFalse` is enforced before bare-witness dispatch, preventing unknown-version witness handling from masking a failing base-script result.
   - Bare witness programs no longer short-circuit out of the interpreter: after `execute_witness_program` succeeds we canonicalize the main stack (`src/script.rs:394-408`), so the downstream CLEANSTACK/unexpected-witness checks behave exactly like Core’s `VerifyScript`.  
   - Regression coverage now includes explicit clean-stack failures for both bare and P2SH-wrapped P2WSH scripts (`src/lib.rs:1308-1365`), ensuring witness scripts that leave stray stack elements surface `ScriptError::CleanStack` just like Core.

Exit criteria: all Bitcoin Core script & transaction test vectors (legacy + SegWit v0) pass bit-for-bit.

---

## Phase 2 – Taproot / Tapscript Support ✅ Completed

Latest parity audit follow-up (against a local Bitcoin Core checkout, February 14, 2026) closed the previously identified consensus-critical deltas listed below. This phase is complete for current Core semantics; subsequent work is maintenance for upstream changes.

1. **Spent Output Plumbing**  
   - Require full previous-output set when Taproot flags are enabled.  
   - Extend `PrecomputedTransactionData` usage so Taproot signature hashing reuses cached values.
   - Taproot witness parser now mirrors Core: annex (if present) is hashed for future sighashes, control blocks are validated (length/modulo 32) and mapped back to tapleaf hashes, and the tweaked key commitment is recomputed in Rust so script-path spends execute under `SigVersion::Taproot`. The `VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION` policy flag is wired up, and tests cover annex handling, malformed control blocks, empty witnesses, and future leaf versions.

2. **Schnorr / BIP340 Verification**  
   - Integrate secp256k1 Schnorr verification (optionally via `external-secp`).  
   - Script-path spending now enforces BIP340 signature sizes, sighash-type rules (implicit `SIGHASH_DEFAULT`, explicit encodings must be non-zero), tapleaf hashing, previous-output lookups, and the tapscript validation-weight decrement that Core uses to cap the SIGOPs/weight ratio. Key-path spends reuse the same helper and validate the tweaked output key in pure Rust. Regression tests cover happy-path key/script signatures, NULLFAIL staying disabled for tapscript, and the discouragement flag for future pubkey encodings.
   - Fresh infrastructure: when the `external-secp` feature is enabled (which now implies `std`), the interpreter borrows the upstream `secp256k1::global::SECP256K1` singleton instead of instantiating ad-hoc verification contexts. Downstream hosts that supply their own libsecp build—or already rely on the global singleton—now reuse that context with zero API changes, while `no_std` builds keep the lightweight per-call context allocation.
   - Bitcoin Core parity check: upstream’s `CountWitnessSigOps` (`src/script/interpreter.cpp:2056-2147`) only charges sigops for witness versions 0 and P2WSH; tapscript witnesses (v1) return zero and instead rely on the validation-weight budget maintained in `ExecutionContext::m_validation_weight_left` (`src/script/interpreter.h:229-237`). Our implementation mirrors that split, so sigop accounting matches Core today.
   - Core still rejects `CHECKMULTISIG(VERIFY)` inside tapscript (`src/script/interpreter.cpp:1108` emits `SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG`, also referenced in `src/script/script_error.cpp:110`), so there are no multisig replacements to port until a future BIP assigns semantics to the reserved OP_SUCCESS slots.
   - Completed parity fix: tapscript now charges validation weight for every non-empty signature before public-key-size branching (including upgradable pubkey types), matching Core’s `EvalChecksigTapscript` sequence.
   - Completed parity fix: witness-v1 dispatch now enforces the BIP341 applicability gate exactly (`version=1`, `program_len=32`, and **not** P2SH-wrapped) before entering Taproot verification.
   - Completed parity fix: witness handling now mirrors Core’s pay-to-anchor carveout (`OP_1 0x024e73`) so non-P2SH anchor spends are accepted while nested `sh(anchor)` stays in the reserved-witness-program path.
   - Runtime optimization: Taproot commitment checks now use direct `xonly tweak_add_check` verification rather than recomputing/tweaking an output key object, reducing overhead in script-path spends while keeping identical semantics.

3. **Tapscript Interpreter Rules**  
   - Enforce Tapscript-specific limits (opcode budget, stack element caps, annex handling, leaf version rules).  
   - Validate control blocks, script tree paths, and tapleaf hashes exactly like Core.
   - `OP_CHECKSIGADD` now behaves exactly like Core: it is only available under `SigVersion::Taproot`, performs Schnorr verification (including validation-weight charging), adds the result to the existing accumulator, and never triggers `NULLFAIL` even when the signature is non-empty. New integration tests cover both the satisfied and unsatisfied branches so stack ordering and arithmetic remain locked in.  
   - `OP_CHECKMULTISIG`/`OP_CHECKMULTISIGVERIFY` are now rejected inside tapscript (`SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG`), and the interpreter scans scripts for the OP_SUCCESS ranges before execution. Unknown OP_SUCCESS opcodes short-circuit to success unless the new `VERIFY_DISCOURAGE_OP_SUCCESS` flag is set, which surfaces `ScriptError::DiscourageOpSuccess` just like Core. Tests cover both the soft-success case and the policy failure. Because Core hasn’t assigned any new semantics to those OP_SUCCESS slots yet, multisig policies are expected to be written using `OP_CHECKSIGADD` loops, so there’s nothing else to port until a future BIP activates.  
   - Added an integration test that mirrors Core’s recommended `multi_a` tapscript multisig: we embed three x-only pubkeys inside the script, loop through `OP_CHECKSIG`/`OP_CHECKSIGADD`, and compare the accumulator against the desired threshold via `OP_NUMEQUAL`. The test signs two of the three slots (plus a negative case) so we validate both success and failure paths in pure Rust and prove our stack ordering matches the descriptor tooling.  
   - Documented the OP_SUCCESS opcode ranges inline (citing Bitcoin Core’s `src/script/script.cpp:IsOpSuccess` at lines 365‑373) so future opcode assignments have a single source of truth inside the interpreter. Core still treats those opcodes as unconditional success paths unless the discourage flag is set, so we follow suit.  
   - MINIMALIF enforcement no longer depends on the policy flag when executing tapscript: every `OP_IF/OP_NOTIF` branch now insists on minimal encodings per BIP342, and diagnostics now distinguish tapscript failures via a dedicated `TapscriptMinimalIf` error path (Core-equivalent to `SCRIPT_ERR_TAPSCRIPT_MINIMALIF`).
   - Script arithmetic continues to use the legacy 4-byte `CScriptNum::nDefaultMaxNumSize` window (`src/script/script.h:243-309`), even under tapscript, matching Bitcoin Core’s consensus behavior today (BIP342 left room for future 64-bit expansion, but Core v26.x has not widened the range). A callout in the interpreter docs highlights this so contributors don’t accidentally widen the range ahead of upstream.
   - Legacy sigop accounting remains unchanged for Taproot spends—Bitcoin Core’s `WitnessSigOps()` helper currently returns `0` for v1 programs and relies entirely on the tapscript validation-weight budget to cap signature checks—so our interpreter mirrors that behaviour. Any future change would have to land upstream first.
   - Completed parity fix: tapscript no longer incorrectly inherits legacy pre-Taproot limits for 10 kB script size or 201 non-push opcount; dedicated regression tests now pin Core’s expected behavior.
   - Latest parity fix: tapscript sighash now commits the last executed `OP_CODESEPARATOR` as an opcode index (matching Core’s `opcode_pos` behavior), not a byte offset. Regression tests cover both the valid opcode-index case and the invalid byte-offset case.
   - Latest hardening: script-code caching now resets per verification and keys by script content digest + codeseparator offset, eliminating stale-cache hazards across script instances.

4. **Cross-Compatibility Tests**  
   - Import Bitcoin Core Taproot test vectors; add custom regression tests for annex, key path, script path (including failures).  
   - Added bespoke coverage for tapscript Schnorr verification (valid/invalid signatures, `CHECKSIGADD` arithmetic, pubkey-type discouragement) so future refactors can be validated without waiting on the upstream vector suite.
   - Parity-audit follow-up completed: explicit key-path-only coverage, signed annex coverage proving annex commits into sighash outcomes, and deeper (multi-node) control-block path coverage matching Core-style `spendpath/*control*` and merkle-path cases.

Exit criteria: Taproot spends (key and script paths) verify identically to Core with and without P2SH wrapping.

---

## Phase 3 – Validation Hardening & Tooling (Ongoing Maintenance)

Status:
- Ongoing quality/performance maintenance track.
- Not a blocker for current Core parity closure captured in Phases 5-6.

1. **Fuzzing & Differential Testing**  
  - Optional extension: wire honggfuzz/AFL targets comparing interpreter output to Core via RPC/FFI harness.  
  - ✅ Added a `proptest`-powered random script differential in `tests/random_consistency.rs` (behind `core-diff`). Each property run synthesizes arbitrary scriptSig/scriptPubKey pairs, executes them through our engine and `libbitcoinconsensus`, and asserts the results match, giving us broad coverage beyond the static Core vectors.  
   - New: `cargo test --features core-diff` replays Bitcoin Core’s `script_tests.json` plus imported tx corpus (`tx_valid.json` / `tx_invalid.json`) through both this crate and `libbitcoinconsensus`, and asserts parity across the shared exposed-flag surface (`P2SH`, `DERSIG`, `NULLDUMMY`, `CLTV`, `CSV`, `WITNESS`, `TAPROOT`).
   - New: `tests/core_sighash_vectors.rs` replays imported Core `sighash.json` vectors to pin legacy sighash compatibility, including `OP_CODESEPARATOR` preprocessing semantics.
   - New: `tests/core_sighash_randomized.rs` adds a deterministic Core-style randomized legacy sighash parity loop (old algorithm vs modern serializer path).
   - New: `tests/core_bip341_wallet_vectors.rs` replays imported Core `bip341_wallet_vectors.json` key-path vectors (intermediary hashes, sighashes, expected signatures, and final verification).
   - New: `tests/script_assets.rs` now runs by default against an in-tree `script_assets_test.json` corpus (still overridable via `SCRIPT_ASSETS_TEST_JSON` / `DIR_UNIT_TEST_DATA`) and also exercises large-corpus checks derived from Core `tx_valid.json`/`tx_invalid.json`.

2. **Performance / Memory Profiling**  
   - ✅ Added a Criterion-based benchmarking harness (`cargo bench --bench verification`) that exercises representative spends (legacy P2PKH, P2SH, P2WSH, Taproot script path) through our interpreter. When `core-diff` is enabled the same harness also measures `libbitcoinconsensus`, giving us side-by-side numbers for future optimizations (stack handling, sighash caching, parser tweaks).  
   - ✅ Applied low-risk hot-path optimizations after Taproot profiling:
     - transaction parsing now uses `deserialize_partial` length checks (no reserialize-for-size pass),
     - precompute hashing writes consensus encoding directly into SHA engines (avoids per-item temporary `Vec` allocations),
     - script/witness handling in critical paths avoids unnecessary byte copies where borrowed slices are sufficient.
   - ✅ Landed: precomputed sighash data is now initialized lazily (first signature opcode only) instead of at verifier entry, which removes unnecessary hashing work on no-signature paths while preserving Core-aligned Taproot readiness checks.
   - Current observation: Taproot script-path remains very close to Core and is workload/host-noise sensitive; repeated longer runs place us around low single-digit deltas. Remaining optimization work should focus on interpreter branch-cost trimming and other parity-safe hot-path reductions.
   - Ensure `no_std` builds remain efficient (minimize allocations, use `alloc` wisely).

3. **Documentation & Maintenance**  
   - Produce detailed module docs (design rationale, deviations, safety notes).  
   - Outline release process, compatibility matrix, and integration tips for downstream crates.

Exit criteria: Robust CI (Linux/macOS/Windows, stable + MSRV), fuzzing gates, and documented guarantees matching `libbitcoinconsensus`.

---

## Phase 4 – Deep Core-Parity Audit Backlog (February 14, 2026)

Status summary:
- The previously recorded parity gaps in this section have been implemented and regression-covered.
- Current residual caveat is proof-surface completeness (continued differential expansion), not a known open consensus mismatch from this backlog.

### Findings (Severity Ranked)

1. **High [Resolved]: `core_tx_vectors` differential silently downgrades flags.**
   - Current behavior: unknown tokens are mapped to zero and still executed as if they were absent.
   - References:
     - `tests/core_tx_vectors.rs:32-55` (`_ => 0` in `parse_flags`)
     - `tests/core_tx_vectors.rs:181-195` (differential still runs after masking)
   - Impact: differential parity can report green while running weaker flag sets than Core vectors specify.

2. **High [Resolved]: Core `sighash_caching` unit logic is not mirrored.**
   - References:
     - Core: `src/test/sighash_tests.cpp:211-300`
     - Current repo: `tests/core_sighash_vectors.rs`, `tests/core_sighash_randomized.rs` (no cache mutation/isolation parity cases)
   - Impact: caching-key and cache-mutation regressions can slip through.

3. **Medium [Resolved]: large-corpus monotonicity in `script_assets` skips many tx vectors due unsupported flag tokens.**
   - References:
     - `tests/script_assets.rs:82-113` (`parse_tx_vector_flags` returns `None` on unknown)
     - `tests/script_assets.rs:244-246` (skipped cases)
   - Impact: reduced coverage over Core `tx_valid.json` / `tx_invalid.json` corpus.

4. **Medium [Resolved]: parser edge-case parity with Core parse tests is incomplete.**
   - References:
     - Core: `src/test/script_parse_tests.cpp:13-55`
     - Current parser helper: `tests/script_asm.rs`
   - Impact: parser behavior drift may go undetected (especially range/error edges).

5. **Medium [Resolved]: error-precedence classification differs for `CLEANSTACK` vs `WITNESS_UNEXPECTED`.**
   - References:
     - Core order: `src/script/interpreter.cpp:2092-2112`
     - Rust order: `src/script.rs:540-546`
   - Impact: usually same fail result, but different `ScriptError` classification in corner cases.

6. **Medium [Resolved]: no direct parity harness for Core sigop count suites.**
   - References:
     - Core: `src/test/sigopcount_tests.cpp:31-231`
     - Current repo sigop tests: `src/script.rs:2780-2806`
   - Impact: sigop-count edge behavior is only partially covered.

7. **Low [Resolved]: script-vector flag parser does not include `DISCOURAGE_UPGRADABLE_PUBKEYTYPE`.**
   - References:
     - Current parser: `tests/script_vectors.rs:248-277`
     - Core token map: `src/test/transaction_tests.cpp:52-74`
   - Impact: future Core vector updates using that token will fail or be partially interpreted.

8. **Low [Accepted]: `script_assets_test.json` is intentionally tiny (curated), not the generated large Core artifact.**
   - References:
     - Local asset file: `tests/data/script_assets_test.json`
     - Core note: `src/test/script_assets_tests.cpp:151-152`
   - Impact: baseline script-assets corpus is small unless augmented by tx-corpus checks.

9. **Audit caveat [Accepted]: this checkout does not currently expose `bitcoinconsensus.cpp` for direct API-entrypoint diff.**
   - Reference:
     - no `bitcoinconsensus.cpp` found under the local Core `src/` tree
   - Impact: API-entrypoint parity proof relies on behavior tests and `bitcoinconsensus` crate differential rather than a direct local C++ source comparison of that wrapper file.

### Implementation Checklists (End-to-End)

#### A. Differential Flag Strictness (`core_tx_vectors` + `script_assets`)
- [x] Replace silent token drop in `tests/core_tx_vectors.rs::parse_flags` with strict parsing.
- [x] Treat `NONE` explicitly as zero flags; reject all other unknown tokens with a recorded skip reason.
- [x] Add counters and final assertions: number of parsed cases, skipped cases, and reasons.
- [x] Fail the test if any non-`BADTX` vector was silently downgraded.
- [x] Apply the same strict/explicit accounting model to `tests/script_assets.rs::parse_tx_vector_flags`.
- [x] Add regression tests for parser behavior in both files (known token, `NONE`, unknown token).
- [x] Update docs with exact coverage counts after implementation.

Current coverage snapshot:
- `core_tx_vectors` and `script_assets` both account for `BADTX`, unknown-token, and non-canonical-combination skips explicitly.
- tx-corpus handling now follows Core semantics (`tx_valid` excluded-flags model, `tx_invalid` direct-flags model) instead of silently weakening vectors.

Acceptance criteria:
- `core_tx_vectors` and `script_assets` print or assert coverage accounting.
- No vector runs with an implicit weaker flag set than declared.

#### B. Sighash Cache Parity Harness (Core `sighash_caching`)
- [x] Add `tests/core_sighash_cache_parity.rs` mirroring Core `sighash_caching` flow.
- [x] Cover both `SigVersion::BASE` and `SigVersion::WITNESS_V0`.
- [x] Cover standard hashtypes and randomized hashtypes (deterministic seed).
- [x] Assert with-cache equals no-cache for unmodified cache state.
- [x] Assert scriptCode/hashType isolation in cache keys.
- [x] Assert explicit cache mutation changes returned hash as expected (except legacy `SIGHASH_SINGLE` out-of-range `ONE` case).  
  - Implemented in `tests/core_sighash_cache_parity.rs::bitcoin_core_style_sighash_cache_mutation_model` with a Core-style cache model; witness-v0 comparisons normalize hashtypes where rust-bitcoin’s API canonicalizes raw values.
- [x] Keep test deterministic and CI-stable.

Acceptance criteria:
- New suite reproduces Core cache invariants, including mutation semantics.

#### C. Parser Edge Tests (Core `script_parse_tests.cpp`)
- [x] Add dedicated parser parity test file (for `tests/script_asm.rs` behavior).
- [x] Port Core happy-path token conversions (`0`, `1..16`, decimals, hex literals, quoted strings, opcode aliases).
- [x] Port Core negative cases:
  - [x] decimal overflow/out-of-range
  - [x] unknown opcode
- [x] Assert exact structured error variants (`BadDecimal`, `DecimalOutOfRange`, `BadOpcode`) and stable messages where applicable.

Acceptance criteria:
- All cases from `src/test/script_parse_tests.cpp:13-55` are represented or intentionally mapped with documented rationale.

#### D. Full `FindAndDelete` Matrix
- [x] Core-style edge matrix exists in `src/script.rs:2842-2969`.
- [x] Add a dedicated parity note in docs that this matrix mirrors `src/test/script_tests.cpp:1495-1602`.
- [x] Add a small harness-level test proving interpreter paths call this logic with matching precedence under:
  - [x] legacy checksig
  - [x] legacy checkmultisig
  - [x] `VERIFY_CONST_SCRIPTCODE` rejection path
- [x] Keep vector-based `FindAndDelete` coverage in `tx_valid.json` / `tx_invalid.json` wired in strict-flag mode (Checklist A).

Acceptance criteria:
- Core edge matrix coverage is explicit and tied to interpreter call paths, not only utility-level tests.

#### E. SigOpcount Parity Harness
- [x] Add a sigopcount parity harness for Core-relevant cases (implemented as expanded unit harness in `src/script.rs`).
- [x] Cover `GetSigOpCount` semantics for:
  - [x] bare scripts
  - [x] accurate vs non-accurate multisig counting
  - [x] P2SH redeem script counting
- [x] Cover witness-related sigop counting semantics aligned with Core `CountWitnessSigOps` behavior.
- [x] Include malformed/truncated script handling parity where relevant.
- [x] Add differential checks where feasible against `bitcoinconsensus` surface.  
  - Implemented in `tests/core_sigop_surface.rs`, mirroring Core-style witness/P2SH-witness toggle scenarios where sigop-path behavior is observable at the verify API surface.
  - Note: the public `bitcoinconsensus` API still does not expose raw sigop counters directly, so this remains surface-level parity rather than direct counter introspection.

Acceptance criteria:
- Test suite demonstrates parity for sigop counting paths that feed consensus-critical limits.

#### F. Error-Precedence Parity (`CLEANSTACK` vs `WITNESS_UNEXPECTED`)
- [x] Add focused regression vectors that trigger both conditions.
- [x] Decide whether to keep current ordering or match Core ordering exactly.
- [x] If matching Core, move checks in `src/script.rs` to Core order and pin with tests.
- [x] Document decision in roadmap and README parity notes.

Acceptance criteria:
- Error-classification behavior is intentional, tested, and documented.

#### G. Coverage and CI Gating
- [x] Add a parity coverage summary section to CI output (or test logs) with:
  - [x] vectors run
  - [x] vectors skipped by reason
  - [x] differential subsets exercised
- [x] Add a "no silent downgrade" CI gate for flag parsers.
- [x] Keep imported Core JSON files hash-checked against local source snapshots when updated.

Acceptance criteria:
- Coverage gaps are explicit at test time, and regressions in harness strictness fail CI.

---

## Phase 5 – Proof-Grade Parity Closure ✅ Completed

Status:
- Completed. This phase closed the proof-surface gaps identified in the deep audit.
- Result: parity evidence is explicit across major Core consensus test paths listed below.

### Workstreams

#### H. `tx_valid` Differential Projection (No More `differential=0`)
- [x] Add a projection path in `tests/core_tx_vectors.rs` that runs `tx_valid` entries through `libbitcoinconsensus` whenever declared flags include policy bits unsupported by the differential bridge.
- [x] Implement deterministic projection rules that map `tx_valid` excluded-flag vectors onto at least one canonical consensus-flag set inside `DIFF_SUPPORTED_FLAGS`.
- [x] Keep current strict token parsing and skip accounting; extend stats with:
  - [x] projected-to-diff count
  - [x] skipped-projection count (with reason)
- [x] Enforce non-zero differential execution for both corpora (`tx_valid` and `tx_invalid`) in test assertions.

Verification criteria:
- [x] `cargo test --features core-diff core_tx_valid_differential -- --nocapture` prints `differential > 0` (current snapshot: `differential=120`, `projected_to_diff=120`).
- [x] `cargo test --features core-diff core_tx_invalid_differential -- --nocapture` still prints `differential > 0` (current snapshot: `differential=70`).
- [x] No unknown token, no silent downgrade, and no projection ambiguity is left unaccounted.

#### I. Mirror Remaining Core C++ Unit Cases as Dedicated Rust Parity Tests
- [x] Add dedicated parity tests for uncovered Core unit flows:
  - [x] `src/test/transaction_tests.cpp:test_witness` mirrored in `tests/core_witness_unit_parity.rs`
  - [x] `src/test/transaction_tests.cpp:spends_witness_prog` mirrored in `tests/core_witness_unit_parity.rs`
  - [x] `src/test/sigopcount_tests.cpp:GetTxSigOpCost` mirrored in `tests/core_sigop_surface.rs`
  - [x] programmatic multisig signing/order paths from `src/test/script_tests.cpp:script_CHECKMULTISIG12` and `src/test/script_tests.cpp:script_CHECKMULTISIG23` mirrored in `tests/core_multisig_unit_parity.rs`
- [x] Keep each new Rust test annotated with the exact Core source case it mirrors.
- [x] Add pass/fail path coverage (not only happy paths), including wrong-key/wrong-witness/wrong-redeem variants where present in Core.

Verification criteria:
- [x] New Rust tests exist and reference their Core counterparts by file + case name.
- [x] `cargo test --features core-diff` passes with the new suites enabled.
- [x] For cases with observable verify API results, differential assertions against `libbitcoinconsensus` are included.

#### J. Import and Run a Larger Generated Script-Assets Corpus
- [x] Replace/augment the tiny curated `tests/data/script_assets_test.json` with a generated large corpus equivalent in spirit to Core's `script_assets_test` usage.  
  - Implemented via deterministic generation from imported Core tx corpora (`tx_valid.json` + `tx_invalid.json`) in `tests/script_assets.rs`.
- [x] Support loading a large corpus in CI and local runs without manual patching of test code.  
  - Default mode auto-generates from vendored Core fixtures; optional override via `SCRIPT_ASSETS_GENERATED_JSON`.
- [x] Keep the curated mini corpus only as a fast smoke fixture; treat generated corpus as the parity-grade fixture.  
  - `script_assets_curated_smoke_monotonicity` runs curated fixture, while `script_assets_generated_corpus_monotonicity` runs large generated corpus.
- [x] Add fixture metadata (source commit/hash/size) and integrity checks similar to existing Core JSON hash pinning.  
  - Added `tests/data/script_assets_generated_metadata.json` and integrity test `script_assets_generated_metadata_integrity`.

Verification criteria:
- [x] Test logs show large-corpus execution (case count significantly above curated fixture size).  
  - Current snapshot: curated `2` cases vs generated `246` cases.
- [x] `cargo test --features core-diff script_assets` runs both curated-smoke and generated corpus modes.
- [x] Fixture integrity checks fail on drift and pass on exact snapshot match.

#### K. Direct Bitcoin Core C++ Runtime Differential Harness (Beyond Crate Bridge)
- [x] Add an optional runtime differential harness that executes comparisons against a locally built Bitcoin Core C++ test/verification surface (not only the Rust `bitcoinconsensus` crate bridge).  
  - Implemented in `tests/core_cpp_runtime_diff.rs` with two backends:
    - current Core (v28+): process-backed helper binary linked against Core internals (`tests/core_cpp_helper/core_consensus_helper.cpp`)
    - legacy fallback: dynamic `libbitcoinconsensus` loading when available.
- [x] Define adapter boundaries explicitly (input serialization, flags, prevouts, expected result mapping).  
  - Harness compares per-input pass/fail for `verify_with_flags_detailed` vs C++ runtime execution with deterministic wire-format requests (flags/index/amount/scriptPubKey/tx/spent-outputs).
- [x] Add deterministic sampling vectors for this harness:
  - [x] selected `script_tests.json` rows (non-placeholder, consensus-flag subset)
  - [x] selected `tx_valid.json`/`tx_invalid.json` rows
  - [x] targeted edge regressions (witness malleation + non-canonical flag-combo precedence; tapscript rows sampled when directly encodable/non-placeholder)
- [x] Gate the harness behind env/config (so default CI remains stable), but enforce it in parity-audit CI job/profile.  
  - Default behavior is explicit skip when no runtime backend is available; parity profile uses `CORE_CPP_DIFF_REQUIRED=1`.

Verification criteria:
- [x] A documented command path runs direct C++ runtime differential checks and reports matched/failed/skipped counts.  
  - Example:  
    `BITCOIN_CORE_REPO=/path/to/bitcoin CORE_CPP_DIFF_BUILD_HELPER=1 cargo test --features core-diff --test core_cpp_runtime_diff -- --nocapture`
- [x] No unchecked mismatch is allowed in the direct harness run for supported vectors.
- [x] Skip reasons (environment/build/path/tooling) are explicit and fail parity-audit profile unless marked accepted.  
  - Parity-audit mode: `CORE_CPP_DIFF_REQUIRED=1 CORE_CPP_DIFF_STRICT=1`  
  - Accepted residual skips can be declared via `CORE_CPP_DIFF_ACCEPTED_SKIPS=<comma-separated-reasons>`.
  - Current strict snapshot (Core helper backend): `compared_inputs=124`, `script_vectors=48`, `tx_valid_vectors=32`, `tx_invalid_vectors=32`, `targeted_cases=2`, accepted residual `unsupported_flags=492`.

### Phase Exit Gates
- [x] `tx_valid` and `tx_invalid` both demonstrate non-zero differential counts.
- [x] All listed uncovered Core unit cases have dedicated Rust mirrors and pass.
- [x] Generated large script-assets corpus is integrated, hash-pinned, and exercised in parity profile.
- [x] Direct C++ runtime differential harness runs successfully with zero untriaged mismatches.
- [x] Roadmap and README parity notes are updated with final coverage numbers and residual accepted caveats (if any).

---

## Phase 6 – Full Runtime Parity Closure ✅ Completed

Status:
- Completed. This phase closed the remaining parity-proof gaps from the deep audit.
- Result: direct C++ runtime differential coverage is in place across the relevant flag and API surface captured by this roadmap.

### Findings Addressed In This Phase (All Resolved)

1. **High [Resolved]: direct Core-runtime differential flag-surface gap (`unsupported_flags`).**
   - Initial condition: helper differential covered only a subset of ScriptVerify flags.
   - Resolution: helper differential now exercises the full supported flag surface; strict helper runs report `skipped_unsupported_flags=0`.

2. **High [Resolved]: API-semantics parity for `amount` vs `spent_outputs` precedence.**
   - Initial condition: Rust behavior could diverge on inconsistent caller inputs.
   - Resolution: runtime contract is Core-aligned (`amount` argument is authoritative for checksig/sighash semantics), with targeted helper differential coverage.

3. **Medium [Resolved]: API-semantics parity for TAPROOT prevouts readiness.**
   - Initial condition: unconditional early TAPROOT+no-prevouts rejection could diverge from Core’s contextual behavior.
   - Resolution: prevouts readiness checks now trigger at the same semantic point as Core (taproot signature-hash/checksig path), with targeted differential vectors.

4. **Medium [Resolved]: ScriptError classification parity in helper differential.**
   - Initial condition: differential harness asserted pass/fail only.
   - Resolution: strict helper runs now assert mapped Core `ScriptError` parity (`unmapped_error_class_comparisons=0`, `error_class_mismatches=0`).

5. **Medium [Resolved]: suite-wide helper differential coverage beyond subset-only checks.**
   - Initial condition: some suites still leaned on subset-only differential paths.
   - Resolution: `core_tx_vectors`, `script_vectors`, and `random_consistency` run helper-backed differential in strict parity profile with explicit skip accounting.

6. **Low [Resolved]: script-assets parity profile now supports upstream minimizer artifact with integrity pinning.**
   - Initial condition: curated + derived corpora were stronger than smoke but not equivalent to upstream minimizer-by-default.
   - Resolution: parity profile enforces upstream artifact flow (`SCRIPT_ASSETS_REQUIRE_UPSTREAM=1`) with metadata/hash checks and committed fallback artifacts under `tests/data/`.

### Workstreams

#### L. Expand Direct C++ Runtime Differential to Full Supported Flag Surface
- [x] Replace helper-backend subset gating with full parse+execution for all known ScriptVerify tokens supported by this crate/Core.
- [x] Keep legacy `libbitcoinconsensus` backend fallback behavior isolated, but do not let it cap helper-backend coverage.
- [x] Add per-flag and per-token coverage counters in helper differential output.
- [x] Make `unsupported_flags` a hard failure in strict parity profile when helper backend is active.

Verification criteria:
- [x] `cargo test --features core-diff --test core_cpp_runtime_diff -- --nocapture` reports `skipped_unsupported_flags=0` in helper mode.
- [x] Strict run with large limits passes without accepted `unsupported_flags` skips:
  - `BITCOIN_CORE_REPO=/path/to/bitcoin CORE_CPP_DIFF_BUILD_HELPER=1 CORE_CPP_DIFF_REQUIRED=1 CORE_CPP_DIFF_STRICT=1 CORE_CPP_DIFF_ACCEPTED_SKIPS=noncanonical_flags,placeholder_vectors CORE_CPP_DIFF_SCRIPT_LIMIT=100000 CORE_CPP_DIFF_TX_LIMIT=100000 cargo test --features core-diff --test core_cpp_runtime_diff -- --nocapture`
  - Current snapshot (helper backend): `supported_flags_mask=0x1fffff`, `compared_inputs=1485`, `script_vectors=1205`, `tx_valid_vectors=120`, `tx_invalid_vectors=84`, `targeted_cases=6`, `skipped_unsupported_flags=0`.

#### M. Resolve Amount/Prevouts API Semantics to Core
- [x] Define and document one compatibility contract:
  - [x] Core-runtime parity contract selected: explicit `amount` is authoritative for signature-hash/checksig semantics.
  - [x] No intentional divergence retained for this surface.
- [x] Remove amount-override behavior; keep structural prevout script consistency checks.
- [x] Add targeted regression+differential cases for inconsistent `(amount, spent_outputs)` inputs:
  - [x] same script/tx with differing explicit amount vs prevout amount
  - [x] witness-v0 checksig path coverage
  - [x] taproot key/script path coverage (closed via Phase N taproot-prevouts semantic alignment and targeted helper differentials)
- [x] Assert pass/fail parity versus helper backend for the new targeted case.

Verification criteria:
- [x] New targeted tests exist and are linked to this finding.
  - `src/lib.rs`: `witness_uses_explicit_amount_even_with_spent_outputs`
  - `tests/core_cpp_runtime_diff.rs`: targeted witness-v0 amount-precedence differential case
- [x] Helper differential targeted cases show no mismatches for inconsistent-input scenarios.
  - Current strict snapshot includes the amount-precedence targeted case with zero mismatches.

#### N. Resolve TAPROOT Prevouts Requirement Semantics to Core
- [x] Move spent-output requirement to the same semantic point Core requires it (taproot signature-hash evaluation path), not an unconditional flag-entry guard.
- [x] Keep taproot readiness checks and fallback/error mapping aligned with current Core interpreter behavior.
- [x] Add targeted differential vectors:
  - [x] TAPROOT flag on non-witness/non-taproot script path with no prevouts
  - [x] TAPROOT flag + witness payload that does not enter taproot signature path
  - [x] actual taproot key/script signature path without prevouts (must fail consistently)

Verification criteria:
- [x] Targeted helper differential tests pass for all above scenarios.
- [x] No early-reject mismatch remains for TAPROOT-bit-only non-taproot execution paths.
- [x] Current strict snapshot (helper backend): `targeted_cases=6`, `skipped_unsupported_flags=0`, zero mismatches.

#### O. Add ScriptError Classification Parity to Direct Helper Differential
- [x] Extend `core_cpp_runtime_diff` assertions from boolean parity to full `(pass/fail + script error)` parity.
- [x] Add explicit **complete** mapping table between Core `ScriptError` integer values and crate `ScriptError` (all currently exposed Core enum values).
- [x] Treat any helper-returned `ScriptError` integer without a mapping as a strict-run failure.
- [x] Track and print:
  - mapped comparisons
  - unmapped comparisons
  - error-class mismatches
- [x] Gate strict parity profile on:
  - `unmapped_comparisons=0`
  - `error_class_mismatches=0`

Verification criteria:
- [x] Strict helper run reports both `unmapped_comparisons=0` and `error_class_mismatches=0`.
- [x] All compared failing cases assert equal error classes across Rust and Core helper.
- [x] Current strict snapshot (helper backend):
  - `compared_inputs=1485`
  - `mapped_error_class_comparisons=1485`
  - `unmapped_error_class_comparisons=0`
  - `error_class_mismatches=0`

#### P. Unify Full-Flag Differential Across `core_tx_vectors`, `script_vectors`, and `random_consistency`
- [x] Add optional helper-backend differential path in each suite, preferring helper when available.
- [x] Ensure no silent fallback to subset-only differential in parity profile.
- [x] Keep explicit skip accounting by reason and fail if unexpected skip classes appear.
- [x] Add parity-profile command(s) that run all three suites with helper-required mode.

Verification criteria:
- [x] `core_tx_vectors`, `script_vectors`, and `random_consistency` each report helper-backed differential execution counts.
- [x] Parity profile fails if helper is unavailable or if comparisons are silently reduced to subset-only mode.
- [x] Current strict helper snapshot:
  - `core_tx_vectors`: `helper_differential=84` (tx-invalid) and `helper_differential=120` (tx-valid), `legacy_differential=0`
  - `script_vectors`: `helper_differential=1209`, `legacy_differential=0`, `skipped_noncanonical=3`
  - `random_consistency`: `helper_differential=256`, `legacy_differential=0`
  - `noncanonical_flags` skip rationale: helper-backed differential intentionally skips non-canonical flag combinations (for example `CLEANSTACK` without `WITNESS`) because current Core `VerifyScript` asserts these invariants in debug builds (`src/script/interpreter.cpp:2098-2099`), which would abort the helper process instead of returning a script result.
  - command:
    - `BITCOIN_CORE_REPO=/path/to/bitcoin CORE_CPP_DIFF_BUILD_HELPER=1 CORE_CPP_DIFF_STRICT=1 CORE_CPP_DIFF_ACCEPTED_SKIPS=noncanonical_flags cargo test --features core-diff --test core_tx_vectors --test script_vectors --test random_consistency -- --nocapture`

#### Q. Script-Assets Corpus Uplift to Upstream Minimizer Artifact
- [x] Add support for consuming a full minimizer-generated `script_assets_test.json` artifact when provided by CI/local environment.
  - `tests/script_assets.rs` now supports:
    - `SCRIPT_ASSETS_UPSTREAM_JSON=/path/to/script_assets_test.json`
    - optional `SCRIPT_ASSETS_USE_DIR_UNIT_TEST_DATA=1` fallback to `DIR_UNIT_TEST_DATA/script_assets_test.json`
- [x] Keep curated fixture as smoke-only baseline, but make large corpus mandatory in parity profile.
  - Curated smoke remains `tests/data/script_assets_test.json` (or `SCRIPT_ASSETS_CURATED_JSON`).
  - Large corpus test enforces `SCRIPT_ASSETS_MIN_CASES` (default `200`) and parity-profile toggles:
    - `SCRIPT_ASSETS_PARITY_PROFILE=1`
    - `SCRIPT_ASSETS_REQUIRE_UPSTREAM=1` to require minimizer artifact source.
- [x] Add metadata and integrity checks (hash + source provenance) for loaded large artifact.
  - Derived corpus integrity remains hash-pinned via `tests/data/script_assets_generated_metadata.json`.
  - Upstream minimizer corpus integrity requires metadata (`SCRIPT_ASSETS_UPSTREAM_METADATA_JSON` or sibling `script_assets_test.metadata.json`) with:
    - `source_core_commit`
    - `source_generation`
    - `artifact_case_count`
    - `artifact_sha256`
- [x] Report case counts and skip reasons separately for curated, derived, and upstream-generated sources.
  - Source-specific coverage summaries now print for:
    - curated smoke
    - derived-from-core-vectors (with explicit generation skip counters)
    - upstream minimizer / derived external files.
- [x] Emit deterministic long-run progress for large corpus sweeps.
  - `script_assets_generated_corpus_monotonicity` now prints start/progress/complete checkpoints.
  - `SCRIPT_ASSETS_PROGRESS_EVERY` controls checkpoint interval (default `100`, set `0` to suppress periodic checkpoints).

Verification criteria:
- [x] Parity profile runs large script-assets corpus and enforces a minimum-case threshold above curated/derived smoke levels.
- [x] Integrity test fails on corpus drift and passes on exact expected artifact.

### Phase 6 Exit Gates
- [x] Direct helper differential runs with `skipped_unsupported_flags=0` and zero untriaged mismatches.
- [x] Amount/prevouts and TAPROOT-prevouts semantics are either Core-aligned and tested, or explicitly documented as intentional divergence (with dedicated compatibility note).
- [x] Error-code parity is asserted in helper differential for mapped cases with zero mismatches.
- [x] `core_tx_vectors`, `script_vectors`, and `random_consistency` parity profile all run helper-backed differential checks.
- [x] Large script-assets corpus (upstream minimizer artifact) is executed in parity profile with integrity pinning.
  - CI wiring is implemented in `.github/workflows/core-parity.yml` and enforces `SCRIPT_ASSETS_REQUIRE_UPSTREAM=1`.
  - Committed fallback artifacts are present: `tests/data/script_assets_upstream.json` and `tests/data/script_assets_upstream_metadata.json` (source generation: `script_assets_test_minimizer`).
  - Known case-`#116` mismatch (`flags=0x20e15`) was fixed by aligning tapscript CHECKSIG/CHECKSIGADD semantics with Core (non-empty invalid Schnorr signatures now hard-fail instead of returning soft-false) and covered by regression test `script::tests::tapscript_non_empty_invalid_signature_aborts_checksigadd`.
- [x] Roadmap + README parity claims updated with post-Phase-6 measured coverage metrics.
  - README now includes a dated parity snapshot section with strict helper differential counters and upstream script-assets corpus execution metrics.

---

## Phase 7 – Residual Proof-Surface Closure (Pre-Implementation)

Status:
- Documented from the deep Core audit (February 16, 2026), with `R`, `S`, `T`, and `U` implemented.
- No newly observed consensus pass/fail mismatch in current strict helper differential runs; this phase closes remaining proof and API-surface gaps.

Latest strict evidence snapshot (before this phase):
- Direct Core helper differential (large limits): `compared_inputs=1485`, `error_class_mismatches=0`, `unmapped_error_class_comparisons=0`, `skipped_unsupported_flags=0`.
- Helper-backed parity suites: `core_tx_vectors`, `script_vectors`, and `random_consistency` all passing.
- Upstream script-assets parity profile: `1791`-case corpus completed successfully with integrity checks.

### Open Findings (Severity Ranked)

- No open findings remain in this phase for the current pinned Core parity scope.

### Workstreams

#### R. Resolve Unknown-Flag API Contract vs Core
- [x] Decide and document target contract:
  - [x] strict validation contract selected: unknown bits are rejected with `ERR_INVALID_FLAGS`.
  - [x] compatibility note: this is an explicit API-surface contract (stricter than direct Core `VerifyScript` entry, which does not globally mask unknown bits).
- [x] Implement selected contract consistently across `verify*` entrypoints.
  - `perform_verification` now validates flags before tx deserialize/index checks, making unknown-bit handling deterministic.
- [x] Add targeted differential/API tests proving intended behavior for unknown-bit inputs.
  - `src/lib.rs`: `verify_with_flags_rejects_unknown_bits_before_tx_deserialize`.
  - `src/lib.rs`: `verify_with_flags_rejects_unknown_bits_before_tx_index_check`.
- [x] Update helper differential harness expectations accordingly.
  - Runtime helper differential remains scoped to known Core flags (`supported_flags_mask`), while unknown-bit behavior is enforced by explicit Rust API tests.

Verification criteria:
- [x] Unknown-bit behavior is intentional, documented, and tested.
- [x] No ambiguous behavior remains between Rust API and declared Core-compatibility contract.

#### S. Close Noncanonical-Flags Differential Blind Spot
- [x] Add explicit noncanonical-flag differential strategy (separate from current canonical-only vector path).
  - Implemented in `tests/core_cpp_runtime_diff.rs`: noncanonical cases are explicitly classified through `should_compare_noncanonical_case` and tracked separately from canonical coverage.
- [x] Ensure harness reports noncanonical coverage counts distinctly from unsupported flags.
  - Runtime output now includes `noncanonical_attempted`, `noncanonical_compared`, `noncanonical_skipped_assert_domain`, and `noncanonical_skipped_unsupported`.
- [x] For cases Core runtime cannot safely execute in helper mode (debug assertions), add deterministic expected-skip policy with explicit acceptance list and rationale.
  - Helper metadata probe (`tests/core_cpp_helper/core_consensus_helper.cpp` `META|asserts=`) is used to detect assert-enabled helper builds; noncanonical differential then records deterministic skip reason `noncanonical_assert_domain` (accepted via `CORE_CPP_DIFF_ACCEPTED_SKIPS`, with backward-compatible alias from `noncanonical_flags`).
- [x] Add targeted noncanonical regressions for known combinations (`WITNESS` without `P2SH`, `CLEANSTACK` without `WITNESS`, etc.).
  - Added targeted noncanonical differential cases in `run_noncanonical_targeted_cases` (`VERIFY_CLEANSTACK`, `VERIFY_CLEANSTACK|VERIFY_P2SH`) and hardened existing `VERIFY_WITNESS` targeted case under the same policy.

Verification criteria:
- [x] Noncanonical differential surface is either executed or explicitly accepted/skipped with zero untriaged cases.
- [x] Parity profile output includes noncanonical attempted/compared/skipped accounting.
  - Current strict snapshot (assert-enabled helper build): `noncanonical_attempted=3`, `noncanonical_compared=0`, `noncanonical_skipped_assert_domain=3`, `noncanonical_skipped_unsupported=0`.

#### T. Mirror Remaining Core Unit Suites 1:1
- [x] Add `tests/core_script_p2sh_unit_parity.rs` mirroring `script_p2sh_tests.cpp` key flows.
  - Added cases for Core `is`, `norecurse`, and `switchover` flows with comments mapped to `src/test/script_p2sh_tests.cpp`.
- [x] Add `tests/core_scriptnum_unit_parity.rs` mirroring `scriptnum_tests.cpp` constructor/operator matrix.
  - Added value/offset matrix derived from Core arrays, with creation/operator parity checks over interpreter-accessible ScriptNum domain (default max size = 4 bytes).
- [x] Add `tests/core_script_segwit_detection_parity.rs` mirroring `script_segwit_tests.cpp` helper-detection matrix.
  - Added `IsPayToWitnessScriptHash_*` and `IsWitnessProgram_*` detection matrix coverage.
- [x] Annotate each test group with exact Core file + case references.

Verification criteria:
- [x] New parity suites pass locally and in CI parity profile.
  - Verified with:
    - `cargo test --test core_script_p2sh_unit_parity`
    - `cargo test --test core_scriptnum_unit_parity`
    - `cargo test --test core_script_segwit_detection_parity`
    - `cargo test --features core-diff --test core_script_p2sh_unit_parity --test core_scriptnum_unit_parity --test core_script_segwit_detection_parity`
- [x] Each mirrored Core unit surface is represented by explicit Rust parity tests (not only indirect vector coverage).

#### U. Parity-Profile Hygiene (Warnings)
- [x] Remove remaining clippy warnings in `core-diff` test targets.
  - Fixed duplicated cfg attribute handling in shared test bridge module and eliminated style warnings in newly added parity suites.
  - Kept high-arity differential helper intentionally with scoped `#[allow(clippy::too_many_arguments)]` to preserve explicit call-site readability for parity cases.
- [x] Add/keep CI clippy gate for `--features core-diff` parity profile path.
  - Added `Clippy parity profile (core-diff)` step in `.github/workflows/core-parity.yml`:
    - `cargo clippy --workspace --all-targets --features core-diff -- -D warnings`

Verification criteria:
- [x] `cargo clippy --workspace --all-targets --features core-diff` is warning-free.

### Phase 7 Exit Gates
- [x] Unknown-flag API semantics are finalized (Core-aligned or intentional divergence) and fully documented/tested.
- [x] Noncanonical flag differential blind spot is closed or explicitly accepted with deterministic policy and accounting.
- [x] Direct mirrors for `script_p2sh_tests`, `scriptnum_tests`, and `script_segwit_tests` are implemented and passing.
- [x] Parity-profile clippy path is warning-free.
