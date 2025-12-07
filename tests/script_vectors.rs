mod script_asm;

use bitcoin::{
    absolute::LockTime,
    blockdata::script::Builder,
    consensus as btc_consensus,
    hex::FromHex,
    transaction::Version,
    Amount,
    OutPoint,
    ScriptBuf,
    Sequence,
    Transaction,
    TxIn,
    TxOut,
    Witness,
};
use consensus::{
    verify_with_flags_detailed, ScriptError, ScriptFailure, VERIFY_CHECKSEQUENCEVERIFY,
    VERIFY_CLEANSTACK, VERIFY_DERSIG, VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, VERIFY_LOW_S, VERIFY_MINIMALDATA,
    VERIFY_MINIMALIF, VERIFY_NULLDUMMY, VERIFY_NULLFAIL, VERIFY_P2SH, VERIFY_SIGPUSHONLY,
    VERIFY_STRICTENC, VERIFY_WITNESS, VERIFY_WITNESS_PUBKEYTYPE,
};
use script_asm::{parse_script, ParseScriptError};
use serde_json::Value;
use std::fmt;

const SCRIPT_TEST_VECTORS: &str = include_str!("data/script_tests.json");

#[test]
fn bitcoin_core_script_vectors() {
    let tests: Vec<Value> =
        serde_json::from_str(SCRIPT_TEST_VECTORS).expect("script_tests.json deserializes");

    let mut skipped = 0usize;
    for (index, test) in tests.into_iter().enumerate() {
        let arr = match test.as_array() {
            Some(arr) => arr,
            None => continue,
        };

        if arr.len() == 1 && arr[0].is_string() {
            continue;
        }

        let mut position = 0usize;
        let mut witness = Witness::new();
        let mut amount = 0u64;

        if arr.get(position).map(|v| v.is_array()).unwrap_or(false) {
            let (stack, sats) = parse_witness_and_amount(&arr[position])
                .unwrap_or_else(|err| panic!("malformed witness entry #{index}: {err}"));
            witness = stack;
            amount = sats;
            position += 1;
        }

        if arr.len() < position + 4 {
            continue;
        }

        let script_sig_str = arr[position].as_str().unwrap_or_else(|| {
            panic!("non-string scriptSig for entry #{index}: {}", arr[position])
        });
        let script_sig = parse_script(script_sig_str)
            .unwrap_or_else(|err| panic_parse(index, err, script_sig_str));
        position += 1;

        let script_pubkey_str = arr[position].as_str().unwrap_or_else(|| {
            panic!(
                "non-string scriptPubKey for entry #{index}: {}",
                arr[position]
            )
        });
        let script_pubkey = parse_script(script_pubkey_str)
            .unwrap_or_else(|err| panic_parse(index, err, script_pubkey_str));
        position += 1;

        let flags_str = arr[position]
            .as_str()
            .unwrap_or_else(|| panic!("non-string flags for entry #{index}: {}", arr[position]));
        let flags = match parse_flags(flags_str) {
            Ok(bits) => bits,
            Err(err) => panic!("entry #{index} invalid flags `{flags_str}`: {err}"),
        };
        position += 1;

        if flags & VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM != 0 && flags & VERIFY_WITNESS == 0
        {
            skipped += 1;
            continue;
        }

        let expected_error_str = arr[position].as_str().unwrap_or_else(|| {
            panic!(
                "non-string expected error for entry #{index}: {}",
                arr[position]
            )
        });
        let expected_error = parse_expected_error(expected_error_str)
            .unwrap_or_else(|| panic!("unknown expected error `{expected_error_str}`"));

        let result = run_vector_case(
            script_sig.clone(),
            script_pubkey.clone(),
            witness.clone(),
            amount,
            flags,
        );

        if index == 612 {
            eprintln!(
                "debug vector 612: result={:?} scriptSigBytes={:x?} scriptSig=`{}` scriptPubKey=`{}` flags={}",
                result,
                script_sig.as_bytes(),
                script_sig_str,
                script_pubkey_str,
                flags_str
            );
        }

        match expected_error {
            None => {
                if let Err(failure) = result {
                    panic!(
                        "vector #{index} expected OK but failed with {:?} flags={} scriptSig=`{}` scriptPubKey=`{}`",
                        failure.script_error, flags, script_sig_str, script_pubkey_str
                    );
                }
            }
            Some(err) => {
                let failure =
                    result.expect_err(&format!("vector #{index} expected {err:?} but succeeded"));
                assert_eq!(
                    failure.script_error, err,
                    "vector #{index} mismatch for expected error {err:?}"
                );
            }
        }
    }

    assert!(
        skipped == 0,
        "skipped {skipped} vectors due to unsupported flag combos"
    );
}

fn panic_parse(index: usize, err: ParseScriptError, asm: &str) -> ! {
    panic!("failed to parse script for entry #{index}: {err} (asm: `{asm}`)");
}

fn run_vector_case(
    script_sig: ScriptBuf,
    script_pubkey: ScriptBuf,
    witness: Witness,
    amount: u64,
    flags: u32,
) -> Result<(), ScriptFailure> {
    let log_truncated_sig = script_sig.as_bytes() == [0x4c, 0x01];
    let credit_tx = Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::default(),
            script_sig: Builder::new().push_int(0).push_int(0).into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: script_pubkey.clone(),
        }],
    };
    let prevout = OutPoint {
        txid: credit_tx.compute_txid(),
        vout: 0,
    };
    let tx = Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prevout,
            script_sig,
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: ScriptBuf::new(),
        }],
    };

    let tx_bytes = btc_consensus::serialize(&tx);
    if log_truncated_sig {
        let hex = tx_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        eprintln!("debug tx bytes for truncated scriptSig: {hex}");
    }
    verify_with_flags_detailed(script_pubkey.as_bytes(), amount, &tx_bytes, None, 0, flags)
}

fn parse_flags(raw: &str) -> Result<u32, FlagError> {
    let mut bits = 0u32;
    for token in raw.split(',').map(|t| t.trim()).filter(|t| !t.is_empty()) {
        let bit = match token {
            "P2SH" => VERIFY_P2SH,
            "STRICTENC" => VERIFY_STRICTENC,
            "DERSIG" => VERIFY_DERSIG,
            "LOW_S" => VERIFY_LOW_S,
            "NULLDUMMY" => VERIFY_NULLDUMMY,
            "SIGPUSHONLY" => VERIFY_SIGPUSHONLY,
            "MINIMALDATA" => VERIFY_MINIMALDATA,
            "DISCOURAGE_UPGRADABLE_NOPS" => VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
            "CLEANSTACK" => VERIFY_CLEANSTACK,
            "CHECKSEQUENCEVERIFY" => VERIFY_CHECKSEQUENCEVERIFY,
            "WITNESS" => VERIFY_WITNESS,
            "MINIMALIF" => VERIFY_MINIMALIF,
            "NULLFAIL" => VERIFY_NULLFAIL,
            "WITNESS_PUBKEYTYPE" => VERIFY_WITNESS_PUBKEYTYPE,
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
            other => return Err(FlagError::Unknown(other.to_string())),
        };
        bits |= bit;
    }
    Ok(bits)
}

#[derive(Debug)]
enum FlagError {
    Unknown(String),
}

impl fmt::Display for FlagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlagError::Unknown(name) => write!(f, "unknown flag `{name}`"),
        }
    }
}

fn parse_witness_and_amount(value: &Value) -> Result<(Witness, u64), String> {
    let arr = value
        .as_array()
        .ok_or_else(|| "witness entry must be array".to_string())?;
    if arr.is_empty() {
        return Err("witness entry missing amount".to_string());
    }

    let mut stack = Vec::with_capacity(arr.len().saturating_sub(1));
    for item in &arr[..arr.len() - 1] {
        let hex = item
            .as_str()
            .ok_or_else(|| "witness stack entries must be strings".to_string())?;
        let bytes = Vec::from_hex(hex).map_err(|_| "invalid witness hex".to_string())?;
        stack.push(bytes);
    }
    let amount = amount_from_value(&arr[arr.len() - 1])?;
    Ok((Witness::from_slice(&stack), amount))
}

fn amount_from_value(value: &Value) -> Result<u64, String> {
    let text = match value {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => return Err("amount must be number or string".into()),
    };
    parse_amount_string(&text)
}

fn parse_amount_string(text: &str) -> Result<u64, String> {
    let mut s = text.trim();
    if s.is_empty() {
        return Err("amount string empty".into());
    }
    if s.starts_with('-') {
        return Err("amount must be non-negative".into());
    }
    if s.starts_with('+') {
        s = &s[1..];
    }

    let mut exponent = 0i32;
    if let Some(pos) = s.find(|c| c == 'e' || c == 'E') {
        let exp_part = s[pos + 1..].trim();
        if exp_part.is_empty() {
            return Err("amount exponent missing".into());
        }
        exponent = exp_part
            .parse::<i32>()
            .map_err(|_| "invalid amount exponent".to_string())?;
        s = &s[..pos];
    }

    let mut digits = String::new();
    let mut frac_len = 0i32;
    let mut seen_dot = false;
    for ch in s.chars() {
        match ch {
            '0'..='9' => {
                digits.push(ch);
                if seen_dot {
                    frac_len += 1;
                }
            }
            '.' => {
                if seen_dot {
                    return Err("amount has multiple decimal points".into());
                }
                seen_dot = true;
            }
            _ => return Err("invalid amount character".into()),
        }
    }

    if digits.is_empty() {
        return Err("amount has no digits".into());
    }

    while digits.starts_with('0') && digits.len() > 1 {
        digits.remove(0);
    }

    let mut value = digits
        .parse::<i128>()
        .map_err(|_| "amount integer part too large".to_string())?;
    let exp = exponent - frac_len + 8;
    if exp >= 0 {
        let factor = 10i128
            .checked_pow(exp as u32)
            .ok_or_else(|| "amount exponent too large".to_string())?;
        value = value
            .checked_mul(factor)
            .ok_or_else(|| "amount out of range".to_string())?;
    } else {
        let divisor = 10i128
            .checked_pow((-exp) as u32)
            .ok_or_else(|| "amount exponent too large".to_string())?;
        if value % divisor != 0 {
            return Err("amount has fractional satoshis".into());
        }
        value /= divisor;
    }

    if value < 0 || value > u64::MAX as i128 {
        return Err("amount out of range".into());
    }
    Ok(value as u64)
}

fn parse_expected_error(raw: &str) -> Option<Option<ScriptError>> {
    use ScriptError::*;
    let err = match raw {
        "OK" => return Some(None),
        "UNKNOWN_ERROR" => ScriptError::Unknown,
        "EVAL_FALSE" => EvalFalse,
        "OP_RETURN" => OpReturn,
        "SCRIPT_SIZE" => ScriptSize,
        "PUSH_SIZE" => PushSize,
        "OP_COUNT" => OpCount,
        "STACK_SIZE" => StackSize,
        "SIG_COUNT" => SigCount,
        "PUBKEY_COUNT" => PubkeyCount,
        "VERIFY" => Verify,
        "EQUALVERIFY" => EqualVerify,
        "DISCOURAGE_UPGRADABLE_NOPS" => DiscourageUpgradableNops,
        "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => DiscourageUpgradableWitnessProgram,
        "DISABLED_OPCODE" => DisabledOpcode,
        "BAD_OPCODE" => BadOpcode,
        "INVALID_STACK_OPERATION" => InvalidStackOperation,
        "INVALID_ALTSTACK_OPERATION" => InvalidAltstackOperation,
        "UNBALANCED_CONDITIONAL" => UnbalancedConditional,
        "NEGATIVE_LOCKTIME" => NegativeLockTime,
        "UNSATISFIED_LOCKTIME" => UnsatisfiedLockTime,
        "SIG_HASHTYPE" => SigHashType,
        "SIG_DER" => SigDer,
        "MINIMALDATA" => MinimalData,
        "SIG_PUSHONLY" => SigPushOnly,
        "SIG_HIGH_S" => SigHighS,
        "SIG_NULLDUMMY" => SigNullDummy,
        "PUBKEYTYPE" => PubkeyType,
        "CLEANSTACK" => CleanStack,
        "MINIMALIF" => MinimalIf,
        "NULLFAIL" => NullFail,
        "WITNESS_PROGRAM_WRONG_LENGTH" => WitnessProgramWrongLength,
        "WITNESS_PROGRAM_WITNESS_EMPTY" => WitnessProgramWitnessEmpty,
        "WITNESS_PROGRAM_MISMATCH" => WitnessProgramMismatch,
        "WITNESS_MALLEATED" => WitnessMalleated,
        "WITNESS_MALLEATED_P2SH" => WitnessMalleatedP2SH,
        "WITNESS_UNEXPECTED" => WitnessUnexpected,
        "WITNESS_PUBKEYTYPE" => WitnessPubkeyType,
        _ => return None,
    };
    Some(Some(err))
}
