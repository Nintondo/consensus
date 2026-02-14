# Integration Roadmap

Goal: replicate the complete `libbitcoinconsensus` behavior in pure Rust while staying source-compatible with `rust-bitcoinconsensus`. Work proceeds in phases so we can ship incremental value and keep parity with Bitcoin Core.

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

3. **Testing Harness – 🚧 In Progress**  
  - Imported the latest `script_tests.json` straight from Bitcoin Core (including the Taproot-only vectors). The Rust harness now understands Core’s placeholder syntax (`#SCRIPT#`, `#CONTROLBLOCK#`, `#TAPROOTOUTPUT#`) and auto-builds the tapleaf/control-block/output key so the JSON stays identical to upstream.  
  - Taproot vector cases automatically feed the interpreter with synthetic `Utxo` entries so BIP341 signature hashing has the prevout context it expects, keeping us in lockstep with `VerifyScript`.  
   - Added focused parity guardrails: `CHECKLOCKTIMEVERIFY` flag token parsing in the script-vector harness, in-repo script-assets subset/superset checks (`tests/script_assets.rs` + `tests/data/script_assets_test.json`) augmented with Core tx-corpus large-corpus checks, plus imported Core data suites for `sighash.json`, `tx_valid.json`, `tx_invalid.json`, and `bip341_wallet_vectors.json`.
   - Fixture integrity gate added: `tests/core_fixture_hashes.rs` pins SHA256 hashes for vendored Core JSON files and, when `BITCOIN_CORE_REPO` points to a local Core checkout, asserts byte-for-byte parity with upstream source files.
   - Still pending: automation to pull fresh JSON corpus revisions from upstream in CI (today the corpora are vendored and exercised, but refresh is still manual).

Exit criteria: ✅ achieved—the crate parses transactions, validates UTXO metadata, and runs today’s interpreter without panicking.

---

## Phase 1 – Script Interpreter Parity (Legacy & P2SH/Witness v0) 🚧 In Progress

1. **Opcode Matrix – 🚧 In Progress (blocked on upstream tapscript multisig semantics)**  
   - Stack/altstack infra plus rotation/tuck/drop ops implemented with depth checks, including the indexed family (`OP_PICK`, `OP_ROLL`, `OP_TUCK`, etc.) and `OP_CODESEPARATOR`.  
   - Numeric helpers, CLTV/CSV, and witness program scaffolding ported.  
   - Arithmetic opcodes now use a faithful ScriptNum parser so operands outside the 32-bit window (or violating MINIMALDATA) raise `ScriptError::Unknown` just like Core; unit tests cover the 2³¹ overflow regression (vector #722).  
   - Per-script limits (opcode budget, stack/altstack bounds, sigop-weighted CHECKMULTISIG accounting) now match Core, and regression tests lock in the `ScriptError::OpCount` path using CHECKSIG-heavy scripts. Execution data now caches code-separator positions, tapleaf hashes, annex bytes, and the tapscript validation-weight budget so the Schnorr paths can share the same bookkeeping Core relies on.

2. **Flag Enforcement – 🚧 In Progress**  
   - `SIGPUSHONLY`, `MINIMALDATA`, `MINIMALIF`, `DISCOURAGE_UPGRADABLE_NOPS`, `CLEANSTACK`, and `NULLFAIL` are wired into the interpreter with targeted regression tests, and flag handling now mirrors Core/libbitcoinconsensus passthrough semantics (supported-bit validation only, no implicit bit promotion for non-canonical combinations).  
   - Newly added: Core’s `CheckSignatureEncoding` semantics (strict DER parsing when DERSIG/STRICTENC/LOW_S are set, low-S enforcement, segwit-only pubkey type enforcement) plus regression tests that cover non-DER malleations, high-S signatures, and uncompressed segwit pubkeys. Internally we now track the interpreter’s `ScriptError` the same way Core does (`Interpreter::last_script_error`), so future differential tests can assert on precise failure reasons even though the public API still reports the coarse `ERR_SCRIPT`.  
   - Fresh progress: `OP_RETURN`, the `*VERIFY` opcode family, and BIP65/BIP112 enforcement now emit Core’s specific `ScriptError`s (including `OpReturn`, `Verify`, `EqualVerify`, `CheckSigVerify`, `CheckMultiSigVerify`, `NumEqualVerify`, `NegativeLockTime`, and `UnsatisfiedLockTime`). Disabled and reserved opcodes are tagged as `DisabledOpcode`/`BadOpcode`, and the regression suite asserts on these diagnostics.  
   - Additional progress: script structural caps now match Core for legacy + Witness v0 paths—the interpreter rejects scripts over 10 kB (`ScriptSize`), pushes over 520 bytes (`PushSize`), and scripts that execute more than 201 opcodes (`OpCount`) where Core enforces those limits. Tapscript keeps Core’s distinct behavior (stack/push limits still enforced, but no legacy 10 kB / 201-opcount gate). We also track legacy + P2SH/Witness sigops exactly like Core so CHECKSIG/CHECKMULTISIG exhaustion is enforced, and regression tests cover the CHECKSIG-heavy worst case. Stack overflows now emit `StackSize`, and multisig argument validation reports `PubkeyCount`/`SigCount`. All of these conditions have regression tests that lock in the precise `ScriptError`.  
   - Latest parity fix: `SCRIPT_VERIFY_CONST_SCRIPTCODE` is now supported end-to-end, including legacy `OP_CODESEPARATOR` rejection and `SIG_FINDANDDELETE` rejection behavior (`OP_CODESEPARATOR` and `SIG_FINDANDDELETE` script errors), with vector-harness mappings aligned to Core’s names.
   - Witness programs now surface the right diagnostics (`WitnessProgramWrongLength`, `WitnessProgramWitnessEmpty`, `WitnessProgramMismatch`, `WitnessMalleated`, `WitnessMalleatedP2SH`, `WitnessUnexpected`, `WitnessPubkeyType`), and SegWit-on-P2SH scriptSigs must be canonical single pushes to match Core’s `WITNESS_MALLEATED_P2SH` rule.  
   - Remaining work: continue rounding out Taproot-only conditions and add Core fixture coverage for sigop accounting edge cases. We also keep this milestone open until Bitcoin Core assigns semantics to the tapscript replacements for `CHECKMULTISIG(VERIFY)`—today the upstream interpreter (`src/script/interpreter.cpp:1108`) still rejects those opcodes with `SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG`, so there is nothing concrete to port. Once Core publishes the new opcode behavior (and corresponding test vectors) we can mirror it immediately to reach full parity.
   - Latest fixes: `CHECKMULTISIG` enforces `NULLFAIL` even when execution aborts early (e.g., leftover signature slots), so the BIP147 regression vectors (#1256) now raise `ScriptError::NullFail` exactly like Core. A dedicated regression test exercises the “`CHECKMULTISIG NOT` hides failure” pattern to keep this behavior locked in.  
   - Latest parity fix: flag semantics now match Core’s API entrypoint behavior for non-canonical combinations (`VERIFY_TAPROOT`-only / `VERIFY_WITNESS`-only): bits are passed through unchanged after supported-bit validation. Regression tests pin both combinations and include differential coverage against `libbitcoinconsensus`.
   - New: when callers supply prevouts (`SpentOutputs`), the verifier now cross-checks the scriptPubKey and derives the satoshi amount directly from the provided UTXO, so SegWit spends no longer need to duplicate the amount alongside the prevout set. TAPROOT verification continues to error unless prevouts are provided. Regression tests cover both behaviors, and `PrecomputedTransactionData` now caches the BIP341 single hashes (amounts/scripts) when Taproot prevouts are present so later Taproot sighash logic can reuse them.

3. **Signature Handling (ECDSA)**  
  - Honor `OP_CODESEPARATOR`, `SigVersion::BASE/WITNESS_V0`, and scriptCode modifications when hashing.  
  - DER parsing now supports Core’s “lax” mode for pre-BIP66 signatures, promotes strict encodings when the relevant flags activate, normalizes signatures before verification so high-S encodings stay valid when LOW_S is disabled, and strips the checked signature from `scriptCode` using a faithful opcode-boundary-aware `FindAndDelete` implementation.  
  - Sigop accounting is already at parity for legacy+SegWit, and the regression suite exercises the NULLFAIL corner-cases so future opcode work cannot accidentally reintroduce the BIP147 bypasses.
  - Latest parity fix: pre-tapscript `CONST_SCRIPTCODE` checksig/checkmultisig paths now follow Core’s error precedence by applying legacy `FindAndDelete` checks before signature/pubkey encoding checks. Targeted regressions pin these classifications.
  - Latest parity fix: `CHECKSEQUENCEVERIFY` now mirrors Core’s `CheckSequence` semantics by enforcing `tx.version >= 2` and comparing masked sequence values (instead of rejecting script operands above `u32::MAX`).
   - Latest parity fix: witness-v0 checksig/checkmultisig now preserve `OP_CODESEPARATOR` bytes in scriptCode (legacy-only stripping), while legacy paths still strip as required.
   - Latest parity fix: witness-v0 sighash now commits the raw hashtype byte exactly like Core (no enum normalization before BIP143 encoding), including non-standard hashtype values.
   - Latest parity fix: `STRICTENC` hashtype validation now masks only `SIGHASH_ANYONECANPAY` (Core’s `IsDefinedHashtypeSignature` behavior), not all high bits.

4. **P2SH & Witness v0 Integration – ✅ Done**  
   - scriptSig push-only enforcement, redeem-script execution, and P2WPKH/P2WSH validation all mirror Bitcoin Core, including the canonical redeem push requirement for P2SH-witness spends.  
   - Bare witness programs no longer short-circuit out of the interpreter: after `execute_witness_program` succeeds we canonicalize the main stack (`src/script.rs:394-408`), so the downstream CLEANSTACK/unexpected-witness checks behave exactly like Core’s `VerifyScript`.  
   - Regression coverage now includes explicit clean-stack failures for both bare and P2SH-wrapped P2WSH scripts (`src/lib.rs:1308-1365`), ensuring witness scripts that leave stray stack elements surface `ScriptError::CleanStack` just like Core.

Exit criteria: all Bitcoin Core script & transaction test vectors (legacy + SegWit v0) pass bit-for-bit.

---

## Phase 2 – Taproot / Tapscript Support 🚧 In Progress

Latest parity audit follow-up (against a local Bitcoin Core checkout, February 14, 2026) closed the previously identified consensus-critical deltas listed below. The phase remains in progress for continued differential hardening and maintenance, not because of known open Taproot consensus mismatches from that audit set.

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

## Phase 3 – Validation Hardening & Tooling

1. **Fuzzing & Differential Testing**  
  - Wire honggfuzz/AFL targets comparing our interpreter output to Core via RPC/FFI harness.  
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
- No newly confirmed pass/fail consensus divergence was found in the main `VerifyScript` control flow versus Core `src/script/interpreter.cpp`.
- A strict "100% parity proven" claim is still blocked by test-harness blind spots and missing mirrors of specific Core unit suites.

### Findings (Severity Ranked)

1. **High: `core_tx_vectors` differential silently downgrades flags.**
   - Current behavior: unknown tokens are mapped to zero and still executed as if they were absent.
   - References:
     - `tests/core_tx_vectors.rs:32-55` (`_ => 0` in `parse_flags`)
     - `tests/core_tx_vectors.rs:181-195` (differential still runs after masking)
   - Impact: differential parity can report green while running weaker flag sets than Core vectors specify.

2. **High: Core `sighash_caching` unit logic is not mirrored.**
   - References:
     - Core: `src/test/sighash_tests.cpp:211-300`
     - Current repo: `tests/core_sighash_vectors.rs`, `tests/core_sighash_randomized.rs` (no cache mutation/isolation parity cases)
   - Impact: caching-key and cache-mutation regressions can slip through.

3. **Medium: large-corpus monotonicity in `script_assets` skips many tx vectors due unsupported flag tokens.**
   - References:
     - `tests/script_assets.rs:82-113` (`parse_tx_vector_flags` returns `None` on unknown)
     - `tests/script_assets.rs:244-246` (skipped cases)
   - Impact: reduced coverage over Core `tx_valid.json` / `tx_invalid.json` corpus.

4. **Medium: parser edge-case parity with Core parse tests is incomplete.**
   - References:
     - Core: `src/test/script_parse_tests.cpp:13-55`
     - Current parser helper: `tests/script_asm.rs`
   - Impact: parser behavior drift may go undetected (especially range/error edges).

5. **Medium: error-precedence classification differs for `CLEANSTACK` vs `WITNESS_UNEXPECTED`.**
   - References:
     - Core order: `src/script/interpreter.cpp:2092-2112`
     - Rust order: `src/script.rs:540-546`
   - Impact: usually same fail result, but different `ScriptError` classification in corner cases.

6. **Medium: no direct parity harness for Core sigop count suites.**
   - References:
     - Core: `src/test/sigopcount_tests.cpp:31-231`
     - Current repo sigop tests: `src/script.rs:2780-2806`
   - Impact: sigop-count edge behavior is only partially covered.

7. **Low: script-vector flag parser does not include `DISCOURAGE_UPGRADABLE_PUBKEYTYPE`.**
   - References:
     - Current parser: `tests/script_vectors.rs:248-277`
     - Core token map: `src/test/transaction_tests.cpp:52-74`
   - Impact: future Core vector updates using that token will fail or be partially interpreted.

8. **Low: `script_assets_test.json` is intentionally tiny (curated), not the generated large Core artifact.**
   - References:
     - Local asset file: `tests/data/script_assets_test.json`
     - Core note: `src/test/script_assets_tests.cpp:151-152`
   - Impact: baseline script-assets corpus is small unless augmented by tx-corpus checks.

9. **Audit caveat: this checkout does not currently expose `bitcoinconsensus.cpp` for direct API-entrypoint diff.**
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

Current coverage snapshot (from `--nocapture` runs):
- `core_tx_vectors` valid corpus: `total=120 executed=66 skipped_unsupported=54`.
- `core_tx_vectors` invalid corpus: `total=93 executed=70 skipped_badtx=9 skipped_unsupported=14`.
- `script_assets` valid corpus: `total=120 parsed=66 checked=66 skipped_unsupported=54`.
- `script_assets` invalid corpus: `total=93 parsed=70 checked=70 skipped_badtx=9 skipped_unsupported=14`.

Acceptance criteria:
- `core_tx_vectors` and `script_assets` print or assert coverage accounting.
- No vector runs with an implicit weaker flag set than declared.

#### B. Sighash Cache Parity Harness (Core `sighash_caching`)
- [x] Add `tests/core_sighash_cache_parity.rs` mirroring Core `sighash_caching` flow.
- [x] Cover both `SigVersion::BASE` and `SigVersion::WITNESS_V0`.
- [x] Cover standard hashtypes and randomized hashtypes (deterministic seed).
- [x] Assert with-cache equals no-cache for unmodified cache state.
- [x] Assert scriptCode/hashType isolation in cache keys.
- [ ] Assert explicit cache mutation changes returned hash as expected (except legacy `SIGHASH_SINGLE` out-of-range `ONE` case).  
  - Note: rust-bitcoin’s public `SighashCache` API does not expose Core-equivalent manual `Store/Load` mutation hooks.
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
