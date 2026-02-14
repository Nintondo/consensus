#![cfg(feature = "core-diff")]

mod script_asm;

use bitcoin::{consensus as btc_consensus, hex::FromHex, OutPoint, ScriptBuf, Transaction, Txid};
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
use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};

const CORE_TX_VALID: &str = include_str!("data/tx_valid.json");
const CORE_TX_INVALID: &str = include_str!("data/tx_invalid.json");

const DIFF_SUPPORTED_FLAGS: u32 = VERIFY_P2SH
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

#[derive(Clone)]
struct PrevoutData {
    script_pubkey: ScriptBuf,
    amount_sat: u64,
}

#[derive(Debug)]
enum FlagParseError {
    UnknownToken(String),
}

#[derive(Default)]
struct DiffCoverageStats {
    total_vectors: usize,
    checked_vectors: usize,
    differential_vectors: usize,
    skipped_badtx: usize,
    unknown_token_counts: BTreeMap<String, usize>,
}

fn parse_flags(raw: &str) -> Result<u32, FlagParseError> {
    if raw.trim().is_empty() || raw == "NONE" {
        return Ok(0);
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
            other => return Err(FlagParseError::UnknownToken(other.to_string())),
        };
        bits |= bit;
    }

    Ok(bits)
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

fn parse_prevouts(raw_inputs: &[Value]) -> HashMap<OutPoint, PrevoutData> {
    let mut out = HashMap::with_capacity(raw_inputs.len());
    for input in raw_inputs {
        let arr = input
            .as_array()
            .expect("input descriptor in tx vector must be an array");
        assert!(
            (3..=4).contains(&arr.len()),
            "input descriptor must have 3 or 4 elements"
        );
        let txid = Txid::from_str(arr[0].as_str().expect("prevout txid must be string"))
            .expect("prevout txid must be valid hex");
        let vout = arr[1].as_i64().expect("prevout index must be integer") as u32;
        let script_pubkey = parse_script(arr[2].as_str().expect("prevout script must be string"))
            .expect("prevout script asm must parse");
        let amount_sat = arr.get(3).and_then(Value::as_i64).unwrap_or(0);
        assert!(amount_sat >= 0, "prevout amount must be non-negative");
        out.insert(
            OutPoint { txid, vout },
            PrevoutData {
                script_pubkey,
                amount_sat: amount_sat as u64,
            },
        );
    }
    out
}

fn run_case_differential(
    tx: &Transaction,
    prevouts: &HashMap<OutPoint, PrevoutData>,
    flags: u32,
    label: &str,
) {
    let tx_bytes = btc_consensus::serialize(tx);
    let mut ordered_prevouts = Vec::with_capacity(tx.input.len());
    let mut script_storage = Vec::with_capacity(tx.input.len());
    for txin in &tx.input {
        let prevout = prevouts
            .get(&txin.previous_output)
            .unwrap_or_else(|| {
                panic!(
                    "missing prevout {:?} for case {label}",
                    txin.previous_output
                )
            })
            .clone();
        script_storage.push(prevout.script_pubkey.as_bytes().to_vec());
        ordered_prevouts.push(prevout);
    }

    let ours_utxos: Vec<Utxo> = ordered_prevouts
        .iter()
        .zip(script_storage.iter())
        .map(|(prevout, script_bytes)| Utxo {
            script_pubkey: script_bytes.as_ptr(),
            script_pubkey_len: script_bytes.len() as u32,
            value: prevout.amount_sat as i64,
        })
        .collect();
    let core_utxos: Vec<bitcoinconsensus::Utxo> = ordered_prevouts
        .iter()
        .zip(script_storage.iter())
        .map(|(prevout, script_bytes)| bitcoinconsensus::Utxo {
            script_pubkey: script_bytes.as_ptr(),
            script_pubkey_len: script_bytes.len() as u32,
            value: prevout.amount_sat as i64,
        })
        .collect();

    let ours_spent = if flags & VERIFY_TAPROOT != 0 {
        Some(ours_utxos.as_slice())
    } else {
        None
    };
    let core_spent = if flags & VERIFY_TAPROOT != 0 {
        Some(core_utxos.as_slice())
    } else {
        None
    };

    for (index, prevout) in ordered_prevouts.iter().enumerate() {
        let ours = verify_with_flags_detailed(
            prevout.script_pubkey.as_bytes(),
            prevout.amount_sat,
            &tx_bytes,
            ours_spent,
            index,
            flags,
        );
        let core = bitcoinconsensus::verify_with_flags(
            prevout.script_pubkey.as_bytes(),
            prevout.amount_sat,
            &tx_bytes,
            core_spent,
            index,
            flags,
        );
        assert_eq!(
            ours.is_ok(),
            core.is_ok(),
            "tx differential mismatch for {label}: input={index} flags={flags:#x} ours={ours:?} core={core:?}"
        );
    }
}

fn run_case_local_expectation(
    tx: &Transaction,
    prevouts: &HashMap<OutPoint, PrevoutData>,
    flags: u32,
    label: &str,
    expect_success: bool,
) {
    let tx_bytes = btc_consensus::serialize(tx);
    let mut ordered_prevouts = Vec::with_capacity(tx.input.len());
    let mut script_storage = Vec::with_capacity(tx.input.len());
    for txin in &tx.input {
        let prevout = prevouts
            .get(&txin.previous_output)
            .unwrap_or_else(|| {
                panic!(
                    "missing prevout {:?} for case {label}",
                    txin.previous_output
                )
            })
            .clone();
        script_storage.push(prevout.script_pubkey.as_bytes().to_vec());
        ordered_prevouts.push(prevout);
    }

    let ours_utxos: Vec<Utxo> = ordered_prevouts
        .iter()
        .zip(script_storage.iter())
        .map(|(prevout, script_bytes)| Utxo {
            script_pubkey: script_bytes.as_ptr(),
            script_pubkey_len: script_bytes.len() as u32,
            value: prevout.amount_sat as i64,
        })
        .collect();
    let ours_spent = if flags & VERIFY_TAPROOT != 0 {
        Some(ours_utxos.as_slice())
    } else {
        None
    };

    let mut any_failed = false;
    for (index, prevout) in ordered_prevouts.iter().enumerate() {
        let ours = verify_with_flags_detailed(
            prevout.script_pubkey.as_bytes(),
            prevout.amount_sat,
            &tx_bytes,
            ours_spent,
            index,
            flags,
        );
        if expect_success {
            assert!(
                ours.is_ok(),
                "tx vector expected success for {label}: input={index} flags={flags:#x} ours={ours:?}"
            );
        } else if ours.is_err() {
            any_failed = true;
        }
    }
    if !expect_success {
        assert!(
            any_failed,
            "tx vector expected failure for {label}: flags={flags:#x}"
        );
    }
}

fn run_tx_vector_file(vectors: &str, expect_success: bool) {
    let tests: Vec<Value> = serde_json::from_str(vectors).expect("tx vectors parse");
    let mut stats = DiffCoverageStats::default();

    for case in tests {
        let arr = match case.as_array() {
            Some(value) => value,
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
        if flags_str == "BADTX" {
            stats.skipped_badtx += 1;
            continue;
        }
        let parsed_flags = match parse_flags(flags_str) {
            Ok(bits) => bits,
            Err(FlagParseError::UnknownToken(token)) => {
                *stats.unknown_token_counts.entry(token).or_insert(0) += 1;
                continue;
            }
        };
        let direct_flags = if expect_success {
            // In tx_valid, the JSON field is the excluded flag mask.
            let included = ALL_TX_VECTOR_FLAGS & !parsed_flags;
            if fill_flags(included) != included {
                continue;
            }
            included
        } else {
            // In tx_invalid, the JSON field is the direct required flag mask.
            if fill_flags(parsed_flags) != parsed_flags {
                continue;
            }
            parsed_flags
        };

        let prevouts = parse_prevouts(arr[0].as_array().expect("inputs array"));
        let tx_hex = arr[1].as_str().expect("serialized tx string");
        let tx_bytes = Vec::from_hex(tx_hex).expect("valid tx hex");
        let tx: Transaction = btc_consensus::deserialize(&tx_bytes).expect("deserializable tx");

        run_case_local_expectation(&tx, &prevouts, direct_flags, tx_hex, expect_success);
        stats.checked_vectors += 1;

        if direct_flags & !DIFF_SUPPORTED_FLAGS == 0 {
            run_case_differential(&tx, &prevouts, direct_flags, tx_hex);
            stats.differential_vectors += 1;
        }
    }

    assert!(
        stats.checked_vectors > 0,
        "core tx vectors executed no checks (total={} badtx={})",
        stats.total_vectors,
        stats.skipped_badtx
    );
    assert!(
        stats.unknown_token_counts.is_empty(),
        "unknown tx-vector flag tokens encountered: {:?}",
        stats.unknown_token_counts
    );
    if !expect_success {
        assert!(
            stats.differential_vectors > 0,
            "core tx vectors executed no libbitcoinconsensus differential checks"
        );
    }

    println!(
        "core_tx_vectors coverage: total={} checked={} differential={} skipped_badtx={}",
        stats.total_vectors, stats.checked_vectors, stats.differential_vectors, stats.skipped_badtx,
    );
}

#[test]
fn core_tx_valid_differential() {
    run_tx_vector_file(CORE_TX_VALID, true);
}

#[test]
fn core_tx_invalid_differential() {
    run_tx_vector_file(CORE_TX_INVALID, false);
}

#[test]
fn parse_flags_accepts_none_and_known_tokens() {
    assert_eq!(parse_flags("NONE").expect("NONE parses"), 0);
    assert_eq!(
        parse_flags("P2SH,WITNESS").expect("known tokens parse"),
        VERIFY_P2SH | VERIFY_WITNESS
    );
}

#[test]
fn parse_flags_rejects_unknown_tokens() {
    assert!(matches!(
        parse_flags("P2SH,NO_SUCH_FLAG"),
        Err(FlagParseError::UnknownToken(_))
    ));
    assert_eq!(
        parse_flags("P2SH,STRICTENC").expect("policy token parses"),
        VERIFY_P2SH | VERIFY_STRICTENC
    );
}
