#![cfg(feature = "core-diff")]

mod script_asm;

use bitcoin::{consensus as btc_consensus, hex::FromHex, OutPoint, ScriptBuf, Transaction, Txid};
use consensus::{
    verify_with_flags_detailed, Utxo, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY,
    VERIFY_DERSIG, VERIFY_NULLDUMMY, VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS,
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

#[derive(Clone)]
struct PrevoutData {
    script_pubkey: ScriptBuf,
    amount_sat: u64,
}

#[derive(Debug)]
enum FlagParseError {
    UnknownToken(String),
    UnsupportedTokens(Vec<String>),
}

#[derive(Default)]
struct DiffCoverageStats {
    total_vectors: usize,
    executed_vectors: usize,
    skipped_badtx: usize,
    skipped_unsupported: usize,
    skipped_noncanonical: usize,
    unsupported_token_counts: BTreeMap<String, usize>,
    unknown_token_counts: BTreeMap<String, usize>,
}

fn parse_flags(raw: &str) -> Result<u32, FlagParseError> {
    if raw.trim().is_empty() || raw == "NONE" {
        return Ok(0);
    }

    let mut bits = 0u32;
    let mut unsupported_tokens = Vec::new();
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        let bit = match token {
            "P2SH" => VERIFY_P2SH,
            "DERSIG" => VERIFY_DERSIG,
            "NULLDUMMY" => VERIFY_NULLDUMMY,
            "CHECKLOCKTIMEVERIFY" => VERIFY_CHECKLOCKTIMEVERIFY,
            "CHECKSEQUENCEVERIFY" => VERIFY_CHECKSEQUENCEVERIFY,
            "WITNESS" => VERIFY_WITNESS,
            "TAPROOT" => VERIFY_TAPROOT,
            // Known Core tokens that this differential does not support because
            // they are outside the libbitcoinconsensus-exposed flag subset.
            "STRICTENC"
            | "LOW_S"
            | "SIGPUSHONLY"
            | "MINIMALDATA"
            | "DISCOURAGE_UPGRADABLE_NOPS"
            | "CLEANSTACK"
            | "MINIMALIF"
            | "NULLFAIL"
            | "CONST_SCRIPTCODE"
            | "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"
            | "WITNESS_PUBKEYTYPE"
            | "DISCOURAGE_UPGRADABLE_PUBKEYTYPE"
            | "DISCOURAGE_OP_SUCCESS"
            | "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" => {
                unsupported_tokens.push(token.to_string());
                continue;
            }
            other => return Err(FlagParseError::UnknownToken(other.to_string())),
        };
        bits |= bit;
    }

    if !unsupported_tokens.is_empty() {
        return Err(FlagParseError::UnsupportedTokens(unsupported_tokens));
    }

    Ok(bits)
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

fn run_tx_vector_file(vectors: &str) {
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
        let direct_flags = match parse_flags(flags_str) {
            Ok(bits) => bits,
            Err(FlagParseError::UnsupportedTokens(tokens)) => {
                stats.skipped_unsupported += 1;
                for token in tokens {
                    *stats.unsupported_token_counts.entry(token).or_insert(0) += 1;
                }
                continue;
            }
            Err(FlagParseError::UnknownToken(token)) => {
                *stats.unknown_token_counts.entry(token).or_insert(0) += 1;
                continue;
            }
        };
        let canonical = |flags: u32| {
            (flags & VERIFY_WITNESS == 0 || flags & VERIFY_P2SH != 0)
                && (flags & VERIFY_TAPROOT == 0 || flags & VERIFY_WITNESS != 0)
        };

        let prevouts = parse_prevouts(arr[0].as_array().expect("inputs array"));
        let tx_hex = arr[1].as_str().expect("serialized tx string");
        let tx_bytes = Vec::from_hex(tx_hex).expect("valid tx hex");
        let tx: Transaction = btc_consensus::deserialize(&tx_bytes).expect("deserializable tx");

        if !canonical(direct_flags) {
            stats.skipped_noncanonical += 1;
            continue;
        }

        debug_assert_eq!(direct_flags & !DIFF_SUPPORTED_FLAGS, 0);
        run_case_differential(&tx, &prevouts, direct_flags, tx_hex);
        stats.executed_vectors += 1;
    }

    assert!(
        stats.executed_vectors > 0,
        "core tx differential executed no vectors (total={} badtx={} unsupported={} noncanonical={})",
        stats.total_vectors,
        stats.skipped_badtx,
        stats.skipped_unsupported,
        stats.skipped_noncanonical
    );
    assert!(
        stats.unknown_token_counts.is_empty(),
        "unknown tx-vector flag tokens encountered: {:?}",
        stats.unknown_token_counts
    );

    println!(
        "core_tx_vectors coverage: total={} executed={} skipped_badtx={} skipped_unsupported={} skipped_noncanonical={} unsupported_breakdown={:?}",
        stats.total_vectors,
        stats.executed_vectors,
        stats.skipped_badtx,
        stats.skipped_unsupported,
        stats.skipped_noncanonical,
        stats.unsupported_token_counts
    );
}

#[test]
fn core_tx_valid_differential() {
    run_tx_vector_file(CORE_TX_VALID);
}

#[test]
fn core_tx_invalid_differential() {
    run_tx_vector_file(CORE_TX_INVALID);
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
fn parse_flags_rejects_unknown_and_unsupported_tokens() {
    assert!(matches!(
        parse_flags("P2SH,NO_SUCH_FLAG"),
        Err(FlagParseError::UnknownToken(_))
    ));
    assert!(matches!(
        parse_flags("P2SH,STRICTENC"),
        Err(FlagParseError::UnsupportedTokens(_))
    ));
}
