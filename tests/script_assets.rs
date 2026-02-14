mod script_asm;

use bitcoin::{consensus as btc_consensus, hex::FromHex, ScriptBuf, Transaction, TxOut, Witness};
use consensus::{
    verify_with_flags_detailed, Utxo, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY,
    VERIFY_CLEANSTACK, VERIFY_CONST_SCRIPTCODE, VERIFY_DERSIG, VERIFY_DISCOURAGE_OP_SUCCESS,
    VERIFY_DISCOURAGE_UPGRADABLE_NOPS, VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
    VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    VERIFY_LOW_S, VERIFY_MINIMALDATA, VERIFY_MINIMALIF, VERIFY_NULLDUMMY, VERIFY_NULLFAIL,
    VERIFY_P2SH, VERIFY_SIGPUSHONLY, VERIFY_STRICTENC, VERIFY_TAPROOT, VERIFY_WITNESS,
    VERIFY_WITNESS_PUBKEYTYPE,
};
use script_asm::parse_script;
use serde_json::Value;
use std::{collections::BTreeMap, env, fs, path::PathBuf};

const CORE_TX_VALID: &str = include_str!("data/tx_valid.json");
const CORE_TX_INVALID: &str = include_str!("data/tx_invalid.json");
const CONSENSUS_FLAGS_MASK: u32 = VERIFY_P2SH
    | VERIFY_DERSIG
    | VERIFY_NULLDUMMY
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS
    | VERIFY_TAPROOT;
const ALL_TX_VECTOR_FLAGS: u32 = VERIFY_P2SH
    | VERIFY_STRICTENC
    | VERIFY_DERSIG
    | VERIFY_LOW_S
    | VERIFY_SIGPUSHONLY
    | VERIFY_MINIMALDATA
    | VERIFY_NULLDUMMY
    | VERIFY_DISCOURAGE_UPGRADABLE_NOPS
    | VERIFY_CLEANSTACK
    | VERIFY_MINIMALIF
    | VERIFY_NULLFAIL
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS
    | VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
    | VERIFY_WITNESS_PUBKEYTYPE
    | VERIFY_CONST_SCRIPTCODE
    | VERIFY_TAPROOT
    | VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE
    | VERIFY_DISCOURAGE_OP_SUCCESS
    | VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION;

fn asset_path() -> PathBuf {
    if let Ok(path) = env::var("SCRIPT_ASSETS_TEST_JSON") {
        return PathBuf::from(path);
    }
    if let Ok(dir) = env::var("DIR_UNIT_TEST_DATA") {
        return PathBuf::from(dir).join("script_assets_test.json");
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/script_assets_test.json")
}

fn all_consensus_flags() -> Vec<u32> {
    let mut flags = Vec::new();
    for bits in 0u32..128 {
        let mut value = 0u32;
        if bits & 1 != 0 {
            value |= VERIFY_P2SH;
        }
        if bits & 2 != 0 {
            value |= VERIFY_DERSIG;
        }
        if bits & 4 != 0 {
            value |= VERIFY_NULLDUMMY;
        }
        if bits & 8 != 0 {
            value |= VERIFY_CHECKLOCKTIMEVERIFY;
        }
        if bits & 16 != 0 {
            value |= VERIFY_CHECKSEQUENCEVERIFY;
        }
        if bits & 32 != 0 {
            value |= VERIFY_WITNESS;
        }
        if bits & 64 != 0 {
            value |= VERIFY_TAPROOT;
        }
        if value & VERIFY_WITNESS != 0 && value & VERIFY_P2SH == 0 {
            continue;
        }
        if value & VERIFY_TAPROOT != 0 && value & VERIFY_WITNESS == 0 {
            continue;
        }
        flags.push(value);
    }
    flags
}

fn trim_flags(flags: u32) -> u32 {
    let mut out = flags;
    // WITNESS requires P2SH.
    if out & VERIFY_P2SH == 0 {
        out &= !VERIFY_WITNESS;
    }
    // CLEANSTACK requires WITNESS (and transitively P2SH).
    if out & VERIFY_WITNESS == 0 {
        out &= !VERIFY_CLEANSTACK;
    }
    out
}

fn fill_flags(flags: u32) -> u32 {
    let mut out = flags;
    // CLEANSTACK implies WITNESS.
    if out & VERIFY_CLEANSTACK != 0 {
        out |= VERIFY_WITNESS;
    }
    // WITNESS implies P2SH.
    if out & VERIFY_WITNESS != 0 {
        out |= VERIFY_P2SH;
    }
    out
}

fn parse_flags(raw: &str) -> u32 {
    let mut bits = 0u32;
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        bits |= match token {
            "P2SH" => VERIFY_P2SH,
            "DERSIG" => VERIFY_DERSIG,
            "NULLDUMMY" => VERIFY_NULLDUMMY,
            "CHECKLOCKTIMEVERIFY" => VERIFY_CHECKLOCKTIMEVERIFY,
            "CHECKSEQUENCEVERIFY" => VERIFY_CHECKSEQUENCEVERIFY,
            "WITNESS" => VERIFY_WITNESS,
            "TAPROOT" => VERIFY_TAPROOT,
            other => panic!("unknown consensus flag in script asset test: {other}"),
        };
    }
    bits
}

#[derive(Debug)]
enum TxVectorFlagParse {
    Parsed(u32),
    Skip(TxVectorSkipReason),
}

#[derive(Debug)]
enum TxVectorSkipReason {
    BadTx,
    UnknownToken(String),
}

#[derive(Default)]
struct MonotonicityStats {
    total_vectors: usize,
    parsed_vectors: usize,
    checked_vectors: usize,
    skipped_badtx: usize,
    skipped_unknown: usize,
    skipped_noncanonical: usize,
    unknown_token_counts: BTreeMap<String, usize>,
}

fn parse_tx_vector_flags(raw: &str) -> TxVectorFlagParse {
    if raw.trim().is_empty() || raw == "NONE" {
        return TxVectorFlagParse::Parsed(0);
    }

    let mut bits = 0u32;
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        let bit = match token {
            "P2SH" => VERIFY_P2SH,
            "STRICTENC" => VERIFY_STRICTENC,
            "DERSIG" => VERIFY_DERSIG,
            "LOW_S" => VERIFY_LOW_S,
            "SIGPUSHONLY" => VERIFY_SIGPUSHONLY,
            "MINIMALDATA" => VERIFY_MINIMALDATA,
            "NULLDUMMY" => VERIFY_NULLDUMMY,
            "DISCOURAGE_UPGRADABLE_NOPS" => VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
            "CLEANSTACK" => VERIFY_CLEANSTACK,
            "MINIMALIF" => VERIFY_MINIMALIF,
            "NULLFAIL" => VERIFY_NULLFAIL,
            "CHECKLOCKTIMEVERIFY" => VERIFY_CHECKLOCKTIMEVERIFY,
            "CHECKSEQUENCEVERIFY" => VERIFY_CHECKSEQUENCEVERIFY,
            "WITNESS" => VERIFY_WITNESS,
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
            "WITNESS_PUBKEYTYPE" => VERIFY_WITNESS_PUBKEYTYPE,
            "CONST_SCRIPTCODE" => VERIFY_CONST_SCRIPTCODE,
            "TAPROOT" => VERIFY_TAPROOT,
            "DISCOURAGE_UPGRADABLE_PUBKEYTYPE" => VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
            "DISCOURAGE_OP_SUCCESS" => VERIFY_DISCOURAGE_OP_SUCCESS,
            "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" => VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
            "BADTX" => return TxVectorFlagParse::Skip(TxVectorSkipReason::BadTx),
            other => {
                return TxVectorFlagParse::Skip(TxVectorSkipReason::UnknownToken(
                    other.to_string(),
                ));
            }
        };
        bits |= bit;
    }

    TxVectorFlagParse::Parsed(bits)
}

fn parse_witness(value: &Value) -> Witness {
    let entries = value
        .as_array()
        .unwrap_or_else(|| panic!("witness field must be an array"));
    let mut stack_items = Vec::with_capacity(entries.len());
    for entry in entries {
        let encoded = entry
            .as_str()
            .unwrap_or_else(|| panic!("witness entries must be hex strings"));
        let bytes = Vec::from_hex(encoded)
            .unwrap_or_else(|_| panic!("invalid witness hex in script asset test"));
        stack_items.push(bytes);
    }
    Witness::from_slice(&stack_items)
}

fn parse_prevouts(value: &Value) -> Vec<TxOut> {
    let entries = value
        .as_array()
        .unwrap_or_else(|| panic!("prevouts field must be an array"));
    let mut prevouts = Vec::with_capacity(entries.len());
    for entry in entries {
        let encoded = entry
            .as_str()
            .unwrap_or_else(|| panic!("prevout entries must be hex strings"));
        let bytes = Vec::from_hex(encoded)
            .unwrap_or_else(|_| panic!("invalid prevout hex in script asset test"));
        let txout = btc_consensus::deserialize::<TxOut>(&bytes)
            .unwrap_or_else(|_| panic!("invalid serialized txout in script asset test"));
        prevouts.push(txout);
    }
    prevouts
}

fn parse_tx_vector_prevouts(value: &Value) -> Vec<TxOut> {
    let entries = value
        .as_array()
        .unwrap_or_else(|| panic!("tx vector prevouts must be an array"));
    let mut prevouts = Vec::with_capacity(entries.len());
    for entry in entries {
        let descriptor = entry
            .as_array()
            .unwrap_or_else(|| panic!("tx vector prevout descriptor must be an array"));
        assert!(
            (3..=4).contains(&descriptor.len()),
            "tx vector prevout descriptor must have 3 or 4 fields"
        );
        let script_pubkey = parse_script(
            descriptor[2]
                .as_str()
                .unwrap_or_else(|| panic!("tx vector prevout script must be string")),
        )
        .unwrap_or_else(|err| panic!("tx vector prevout script asm parse failed: {err}"));
        let amount_sat = descriptor.get(3).and_then(Value::as_i64).unwrap_or(0);
        assert!(
            amount_sat >= 0,
            "tx vector prevout amounts must be non-negative"
        );
        prevouts.push(TxOut {
            value: bitcoin::Amount::from_sat(amount_sat as u64),
            script_pubkey,
        });
    }
    prevouts
}

fn verify_case(
    tx: &Transaction,
    prevouts: &[TxOut],
    input_index: usize,
    flags: u32,
) -> Result<(), consensus::ScriptFailure> {
    let tx_bytes = btc_consensus::serialize(tx);
    let spent_script = prevouts[input_index].script_pubkey.as_bytes();
    let amount = prevouts[input_index].value.to_sat();

    if flags & VERIFY_TAPROOT == 0 {
        return verify_with_flags_detailed(
            spent_script,
            amount,
            &tx_bytes,
            None,
            input_index,
            flags,
        );
    }

    let script_storage: Vec<Vec<u8>> = prevouts
        .iter()
        .map(|txout| txout.script_pubkey.as_bytes().to_vec())
        .collect();
    let utxos: Vec<Utxo> = prevouts
        .iter()
        .zip(script_storage.iter())
        .map(|(txout, script)| Utxo {
            script_pubkey: script.as_ptr(),
            script_pubkey_len: script.len() as u32,
            value: txout.value.to_sat() as i64,
        })
        .collect();

    verify_with_flags_detailed(
        spent_script,
        amount,
        &tx_bytes,
        Some(&utxos),
        input_index,
        flags,
    )
}

fn run_core_tx_monotonicity(vectors: &str, expect_success: bool) {
    let cases: Vec<Value> = serde_json::from_str(vectors).expect("core tx vectors parse");
    let consensus_flags = all_consensus_flags();
    let mut checked = 0usize;
    let mut stats = MonotonicityStats::default();

    for case in cases {
        let arr = match case.as_array() {
            Some(arr) => arr,
            None => continue,
        };
        if arr.len() == 1 && arr[0].is_string() {
            continue;
        }
        if arr.len() != 3 || !arr[0].is_array() || !arr[1].is_string() || !arr[2].is_string() {
            continue;
        }
        stats.total_vectors += 1;

        let flags_str = arr[2].as_str().expect("flags string");
        let parsed_flags = match parse_tx_vector_flags(flags_str) {
            TxVectorFlagParse::Parsed(flags) => {
                stats.parsed_vectors += 1;
                flags
            }
            TxVectorFlagParse::Skip(TxVectorSkipReason::BadTx) => {
                stats.skipped_badtx += 1;
                continue;
            }
            TxVectorFlagParse::Skip(TxVectorSkipReason::UnknownToken(token)) => {
                stats.skipped_unknown += 1;
                *stats.unknown_token_counts.entry(token).or_insert(0) += 1;
                continue;
            }
        };
        let prevouts = parse_tx_vector_prevouts(&arr[0]);
        let tx_hex = arr[1].as_str().expect("serialized tx string");
        let tx: Transaction = btc_consensus::deserialize(
            &Vec::from_hex(tx_hex).expect("core tx vector serialized transaction hex"),
        )
        .expect("core tx vector serialized transaction decode");

        if tx.input.len() != prevouts.len() {
            continue;
        }

        if expect_success {
            // In Core's tx_valid corpus the JSON field carries excluded flags.
            let included_flags = ALL_TX_VECTOR_FLAGS & !parsed_flags;
            if fill_flags(included_flags) != included_flags {
                stats.skipped_noncanonical += 1;
                continue;
            }
            let fixed_non_consensus = included_flags & !CONSENSUS_FLAGS_MASK;
            let included_consensus = included_flags & CONSENSUS_FLAGS_MASK;

            for consensus_bits in &consensus_flags {
                if (consensus_bits & included_consensus) != *consensus_bits {
                    continue;
                }
                let flags = trim_flags(fixed_non_consensus | *consensus_bits);
                for input_index in 0..tx.input.len() {
                    let result = verify_case(&tx, &prevouts, input_index, flags);
                    assert!(
                        result.is_ok(),
                        "core tx-valid monotonicity mismatch: input={input_index} excluded_flags={parsed_flags:#x} flags={flags:#x} tx={tx_hex} result={result:?}"
                    );
                }
                checked += 1;
                stats.checked_vectors += 1;
            }
        } else {
            // In Core's tx_invalid corpus the JSON field carries direct required
            // flags. Failure should hold for supersets.
            let required_flags = fill_flags(parsed_flags);
            if required_flags != parsed_flags {
                stats.skipped_noncanonical += 1;
                continue;
            }
            let fixed_non_consensus = required_flags & !CONSENSUS_FLAGS_MASK;
            let required_consensus = required_flags & CONSENSUS_FLAGS_MASK;

            for consensus_bits in &consensus_flags {
                if (consensus_bits & required_consensus) != required_consensus {
                    continue;
                }
                let flags = fill_flags(fixed_non_consensus | *consensus_bits);
                let mut any_failed = false;
                for input_index in 0..tx.input.len() {
                    let result = verify_case(&tx, &prevouts, input_index, flags);
                    if result.is_err() {
                        any_failed = true;
                        break;
                    }
                }
                assert!(
                    any_failed,
                    "core tx-invalid monotonicity mismatch: required_flags={parsed_flags:#x} flags={flags:#x} tx={tx_hex}"
                );
                checked += 1;
                stats.checked_vectors += 1;
            }
        }
    }

    assert!(
        checked > 0,
        "core tx monotonicity checks must execute cases"
    );
    assert!(
        stats.unknown_token_counts.is_empty(),
        "unknown tx-vector flag tokens in monotonicity harness: {:?}",
        stats.unknown_token_counts
    );
    println!(
        "script_assets coverage (expect_success={}): total={} parsed={} checked={} skipped_badtx={} skipped_noncanonical={}",
        expect_success,
        stats.total_vectors,
        stats.parsed_vectors,
        stats.checked_vectors,
        stats.skipped_badtx,
        stats.skipped_noncanonical
    );
}

#[test]
fn parse_tx_vector_flags_accepts_none_and_known_tokens() {
    assert!(matches!(
        parse_tx_vector_flags("NONE"),
        TxVectorFlagParse::Parsed(0)
    ));
    assert!(matches!(
        parse_tx_vector_flags("P2SH,WITNESS"),
        TxVectorFlagParse::Parsed(flags) if flags == (VERIFY_P2SH | VERIFY_WITNESS)
    ));
}

#[test]
fn parse_tx_vector_flags_rejects_unknown_tokens() {
    assert!(matches!(
        parse_tx_vector_flags("P2SH,NO_SUCH_FLAG"),
        TxVectorFlagParse::Skip(TxVectorSkipReason::UnknownToken(_))
    ));
    assert!(matches!(
        parse_tx_vector_flags("P2SH,STRICTENC"),
        TxVectorFlagParse::Parsed(flags) if flags == (VERIFY_P2SH | VERIFY_STRICTENC)
    ));
}

#[test]
fn script_assets_flag_monotonicity() {
    let path = asset_path();
    assert!(
        path.exists(),
        "script assets file does not exist: {}",
        path.display()
    );

    let raw = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "failed to read script assets file {}: {err}",
            path.display()
        )
    });
    let tests: Value = serde_json::from_str(&raw).unwrap_or_else(|err| {
        panic!(
            "failed to parse script assets JSON {}: {err}",
            path.display()
        )
    });
    let entries = tests
        .as_array()
        .unwrap_or_else(|| panic!("script assets top-level JSON must be an array"));
    assert!(!entries.is_empty(), "script assets JSON is empty");

    let consensus_flags = all_consensus_flags();
    for (idx, case) in entries.iter().enumerate() {
        let obj = case
            .as_object()
            .unwrap_or_else(|| panic!("script asset case #{idx} must be an object"));
        let base_tx_hex = obj
            .get("tx")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("script asset case #{idx} missing tx"));
        let tx_bytes = Vec::from_hex(base_tx_hex)
            .unwrap_or_else(|_| panic!("script asset case #{idx} has invalid tx hex"));
        let mut tx = btc_consensus::deserialize::<Transaction>(&tx_bytes)
            .unwrap_or_else(|_| panic!("script asset case #{idx} tx failed to deserialize"));
        let prevouts = parse_prevouts(
            obj.get("prevouts")
                .unwrap_or_else(|| panic!("script asset case #{idx} missing prevouts")),
        );
        let input_index = obj
            .get("index")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("script asset case #{idx} missing index"))
            as usize;
        assert_eq!(
            prevouts.len(),
            tx.input.len(),
            "script asset case #{idx} prevout count mismatch"
        );
        assert!(
            input_index < tx.input.len(),
            "script asset case #{idx} input index out of range"
        );

        let test_flags = parse_flags(
            obj.get("flags")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("script asset case #{idx} missing flags")),
        );
        let final_case = obj.get("final").and_then(Value::as_bool).unwrap_or(false);

        if let Some(success) = obj.get("success") {
            let success_obj = success
                .as_object()
                .unwrap_or_else(|| panic!("script asset case #{idx} success must be object"));
            let script_sig_hex = success_obj
                .get("scriptSig")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("script asset case #{idx} success missing scriptSig"));
            let script_sig =
                ScriptBuf::from_bytes(Vec::from_hex(script_sig_hex).unwrap_or_else(|_| {
                    panic!("script asset case #{idx} has invalid success scriptSig")
                }));
            let witness = parse_witness(
                success_obj
                    .get("witness")
                    .unwrap_or_else(|| panic!("script asset case #{idx} success missing witness")),
            );
            tx.input[input_index].script_sig = script_sig;
            tx.input[input_index].witness = witness;

            for flags in &consensus_flags {
                if final_case || ((flags & test_flags) == *flags) {
                    let result = verify_case(&tx, &prevouts, input_index, *flags);
                    assert!(
                        result.is_ok(),
                        "script asset case #{idx} expected success for flags {flags:#x}, got {result:?}"
                    );
                }
            }
        }

        if let Some(failure) = obj.get("failure") {
            let failure_obj = failure
                .as_object()
                .unwrap_or_else(|| panic!("script asset case #{idx} failure must be object"));
            let script_sig_hex = failure_obj
                .get("scriptSig")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("script asset case #{idx} failure missing scriptSig"));
            let script_sig =
                ScriptBuf::from_bytes(Vec::from_hex(script_sig_hex).unwrap_or_else(|_| {
                    panic!("script asset case #{idx} has invalid failure scriptSig")
                }));
            let witness = parse_witness(
                failure_obj
                    .get("witness")
                    .unwrap_or_else(|| panic!("script asset case #{idx} failure missing witness")),
            );
            tx.input[input_index].script_sig = script_sig;
            tx.input[input_index].witness = witness;

            for flags in &consensus_flags {
                if (flags & test_flags) == test_flags {
                    let result = verify_case(&tx, &prevouts, input_index, *flags);
                    assert!(
                        result.is_err(),
                        "script asset case #{idx} expected failure for flags {flags:#x}"
                    );
                }
            }
        }
    }
}

#[test]
fn script_assets_monotonicity_over_core_tx_valid_vectors() {
    run_core_tx_monotonicity(CORE_TX_VALID, true);
}

#[test]
fn script_assets_core_tx_invalid_exact_flag_failures() {
    run_core_tx_monotonicity(CORE_TX_INVALID, false);
}
