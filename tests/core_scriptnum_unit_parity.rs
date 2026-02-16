use bitcoin::{
    absolute::LockTime,
    blockdata::script::{Builder, PushBytesBuf},
    consensus as btc_consensus,
    opcodes::{all, Opcode},
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use consensus::{verify_with_flags_detailed, ScriptError, ScriptFailure, VERIFY_NONE};

// Mirrors value/offset sets used by Bitcoin Core src/test/scriptnum_tests.cpp.
const VALUES: [i64; 13] = [
    0,
    1,
    -2,
    127,
    128,
    -255,
    256,
    (1i64 << 15) - 1,
    -(1i64 << 16),
    (1i64 << 24) - 1,
    1i64 << 31,
    1 - (1i64 << 32),
    1i64 << 40,
];

const OFFSETS: [i64; 9] = [1, 0x79, 0x80, 0x81, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x10000];

fn spending_tx(script_sig: ScriptBuf) -> Transaction {
    Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::default(),
            script_sig,
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

fn run_script(script_sig: ScriptBuf, script_pubkey: ScriptBuf) -> Result<(), ScriptFailure> {
    let tx = spending_tx(script_sig);
    let tx_bytes = btc_consensus::serialize(&tx);
    let ours =
        verify_with_flags_detailed(script_pubkey.as_bytes(), 0, &tx_bytes, None, 0, VERIFY_NONE);

    #[cfg(feature = "core-diff")]
    {
        let core = bitcoinconsensus::verify_with_flags(
            script_pubkey.as_bytes(),
            0,
            &tx_bytes,
            None,
            0,
            VERIFY_NONE,
        );
        assert_eq!(
            ours.is_ok(),
            core.is_ok(),
            "Core mismatch for scriptnum parity: ours={ours:?} core={core:?}"
        );
    }

    ours
}

fn encode_scriptnum(num: i64) -> Vec<u8> {
    if num == 0 {
        return Vec::new();
    }

    let negative = num < 0;
    let mut abs = if negative { (-num) as u64 } else { num as u64 };
    let mut out = Vec::new();
    while abs > 0 {
        out.push((abs & 0xff) as u8);
        abs >>= 8;
    }

    if out[out.len() - 1] & 0x80 != 0 {
        out.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = out.len() - 1;
        out[last] |= 0x80;
    }

    out
}

fn push_scriptnum(builder: Builder, num: i64) -> Builder {
    builder.push_slice(PushBytesBuf::try_from(encode_scriptnum(num)).expect("scriptnum push bytes"))
}

fn fits_default_scriptnum(num: i64) -> bool {
    encode_scriptnum(num).len() <= 4
}

fn assert_script_ok(script_sig: ScriptBuf, script_pubkey: ScriptBuf, context: &str) {
    run_script(script_sig, script_pubkey).unwrap_or_else(|failure| {
        panic!("{context}: expected success, got {failure:?}");
    });
}

fn assert_script_unknown(script_sig: ScriptBuf, script_pubkey: ScriptBuf, context: &str) {
    let failure = run_script(script_sig, script_pubkey).expect_err(context);
    assert_eq!(
        failure.script_error,
        ScriptError::Unknown,
        "{context}: expected ScriptError::Unknown, got {failure:?}"
    );
}

fn assert_creation_case(num: i64) {
    // OP_ADD with zero forces ScriptNum decode/encode through the same interpreter path
    // exercised by Core's CScriptNum roundtrip tests.
    let script_sig = push_scriptnum(push_scriptnum(Builder::new(), num), 0).into_script();
    let script_pubkey = push_scriptnum(Builder::new().push_opcode(all::OP_ADD), num)
        .push_opcode(all::OP_NUMEQUAL)
        .into_script();

    let context = format!("creation case num={num}");
    if fits_default_scriptnum(num) {
        assert_script_ok(script_sig, script_pubkey, &context);
    } else {
        assert_script_unknown(script_sig, script_pubkey, &context);
    }
}

fn assert_binary_op_case(a: i64, b: i64, opcode: Opcode, expected: i64, context: &str) {
    let script_sig = push_scriptnum(push_scriptnum(Builder::new(), a), b).into_script();
    let script_pubkey = push_scriptnum(Builder::new().push_opcode(opcode), expected)
        .push_opcode(all::OP_NUMEQUAL)
        .into_script();
    assert_script_ok(script_sig, script_pubkey, context);
}

fn assert_compare_case(a: i64, b: i64, opcode: Opcode, expected: bool, context: &str) {
    let expected_num = if expected { 1 } else { 0 };
    assert_binary_op_case(a, b, opcode, expected_num, context);
}

fn assert_negate_case(num: i64, expected: i64, context: &str) {
    let script_sig = push_scriptnum(Builder::new(), num).into_script();
    let script_pubkey = push_scriptnum(Builder::new().push_opcode(all::OP_NEGATE), expected)
        .push_opcode(all::OP_NUMEQUAL)
        .into_script();
    assert_script_ok(script_sig, script_pubkey, context);
}

fn run_operator_pair(a: i64, b: i64) {
    if !fits_default_scriptnum(a) || !fits_default_scriptnum(b) {
        return;
    }

    if let Some(sum) = a
        .checked_add(b)
        .filter(|value| fits_default_scriptnum(*value))
    {
        assert_binary_op_case(a, b, all::OP_ADD, sum, &format!("add {a} + {b}"));
    }
    if let Some(diff) = a
        .checked_sub(b)
        .filter(|value| fits_default_scriptnum(*value))
    {
        assert_binary_op_case(a, b, all::OP_SUB, diff, &format!("sub {a} - {b}"));
    }
    if let Some(neg) = a
        .checked_neg()
        .filter(|value| fits_default_scriptnum(*value))
    {
        assert_negate_case(a, neg, &format!("negate {a}"));
    }

    assert_compare_case(a, b, all::OP_NUMEQUAL, a == b, &format!("eq {a} == {b}"));
    assert_compare_case(a, b, all::OP_NUMNOTEQUAL, a != b, &format!("ne {a} != {b}"));
    assert_compare_case(a, b, all::OP_LESSTHAN, a < b, &format!("lt {a} < {b}"));
    assert_compare_case(a, b, all::OP_GREATERTHAN, a > b, &format!("gt {a} > {b}"));
    assert_compare_case(
        a,
        b,
        all::OP_LESSTHANOREQUAL,
        a <= b,
        &format!("le {a} <= {b}"),
    );
    assert_compare_case(
        a,
        b,
        all::OP_GREATERTHANOREQUAL,
        a >= b,
        &format!("ge {a} >= {b}"),
    );
}

// Mirrors Bitcoin Core src/test/scriptnum_tests.cpp:creation
// for interpreter-accessible ScriptNum domain (default max size = 4 bytes).
#[test]
fn core_scriptnum_tests_creation_matrix_default_max_num_size() {
    for value in VALUES {
        for offset in OFFSETS {
            assert_creation_case(value);
            assert_creation_case(value + offset);
            assert_creation_case(value - offset);
        }
    }
}

// Mirrors Bitcoin Core src/test/scriptnum_tests.cpp:operators
// for interpreter-accessible ScriptNum domain (default max size = 4 bytes).
#[test]
fn core_scriptnum_tests_operator_matrix_default_max_num_size() {
    for value in VALUES {
        for base in VALUES.iter().take(OFFSETS.len()).copied() {
            let pairs = [
                (value, value),
                (value, -value),
                (value, base),
                (value, -base),
                (value + base, base),
                (value + base, -base),
                (value - base, base),
                (value - base, -base),
                (value + base, value + base),
                (value + base, value - base),
                (value - base, value + base),
                (value - base, value - base),
            ];

            for (a, b) in pairs {
                run_operator_pair(a, b);
            }
        }
    }
}
