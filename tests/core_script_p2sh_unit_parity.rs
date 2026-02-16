use bitcoin::{
    absolute::LockTime,
    blockdata::script::{Builder, PushBytesBuf},
    consensus as btc_consensus,
    opcodes::all,
    transaction::Version,
    Amount, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use consensus::{verify_with_flags_detailed, ScriptError, ScriptFailure, VERIFY_NONE, VERIFY_P2SH};

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

fn assert_verify_matches_core(
    spent_script: &ScriptBuf,
    tx: &Transaction,
    flags: u32,
) -> Result<(), ScriptFailure> {
    let tx_bytes = btc_consensus::serialize(tx);
    let ours = verify_with_flags_detailed(spent_script.as_bytes(), 0, &tx_bytes, None, 0, flags);

    #[cfg(feature = "core-diff")]
    {
        let core = bitcoinconsensus::verify_with_flags(
            spent_script.as_bytes(),
            0,
            &tx_bytes,
            None,
            0,
            flags,
        );
        assert_eq!(
            ours.is_ok(),
            core.is_ok(),
            "Core mismatch for script_p2sh_tests parity case: flags={flags:#x} ours={ours:?} core={core:?}"
        );
    }

    ours
}

fn push_data_script(data: &[u8]) -> ScriptBuf {
    Builder::new()
        .push_slice(PushBytesBuf::try_from(data.to_vec()).expect("push-data bytes"))
        .into_script()
}

// Mirrors Bitcoin Core src/test/script_p2sh_tests.cpp:is.
#[test]
fn core_script_p2sh_tests_is_detection_matrix() {
    let mut canonical = vec![all::OP_HASH160.to_u8(), 20];
    canonical.extend([0u8; 20]);
    canonical.push(all::OP_EQUAL.to_u8());
    assert!(Script::from_bytes(&canonical).is_p2sh());

    let mut pushdata1 = vec![all::OP_HASH160.to_u8(), all::OP_PUSHDATA1.to_u8(), 20];
    pushdata1.extend([0u8; 20]);
    pushdata1.push(all::OP_EQUAL.to_u8());
    assert!(!Script::from_bytes(&pushdata1).is_p2sh());

    let mut pushdata2 = vec![all::OP_HASH160.to_u8(), all::OP_PUSHDATA2.to_u8(), 20, 0];
    pushdata2.extend([0u8; 20]);
    pushdata2.push(all::OP_EQUAL.to_u8());
    assert!(!Script::from_bytes(&pushdata2).is_p2sh());

    let mut pushdata4 = vec![
        all::OP_HASH160.to_u8(),
        all::OP_PUSHDATA4.to_u8(),
        20,
        0,
        0,
        0,
    ];
    pushdata4.extend([0u8; 20]);
    pushdata4.push(all::OP_EQUAL.to_u8());
    assert!(!Script::from_bytes(&pushdata4).is_p2sh());

    assert!(!ScriptBuf::new().is_p2sh());
    assert!(!Builder::new()
        .push_opcode(all::OP_HASH160)
        .push_opcode(all::OP_PUSHBYTES_20)
        .push_opcode(all::OP_PUSHBYTES_20)
        .push_opcode(all::OP_EQUAL)
        .into_script()
        .is_p2sh());
    assert!(!Builder::new()
        .push_opcode(all::OP_NOP)
        .push_opcode(all::OP_PUSHBYTES_20)
        .push_opcode(all::OP_EQUAL)
        .into_script()
        .is_p2sh());
}

// Mirrors Bitcoin Core src/test/script_p2sh_tests.cpp:norecurse.
#[test]
fn core_script_p2sh_tests_norecurse_parity() {
    let invalid_as_script = Builder::new()
        .push_opcode(all::OP_INVALIDOPCODE)
        .push_opcode(all::OP_INVALIDOPCODE)
        .into_script();
    let p2sh = ScriptBuf::new_p2sh(&invalid_as_script.script_hash());

    let tx_non_recursive = spending_tx(push_data_script(invalid_as_script.as_bytes()));
    let non_recursive_failure = assert_verify_matches_core(&p2sh, &tx_non_recursive, VERIFY_P2SH)
        .expect_err("single-layer p2sh should execute redeem script and fail");
    assert_eq!(non_recursive_failure.script_error, ScriptError::BadOpcode);

    let p2sh2 = ScriptBuf::new_p2sh(&p2sh.script_hash());
    let script_sig2 = Builder::new()
        .push_slice(
            PushBytesBuf::try_from(invalid_as_script.as_bytes().to_vec())
                .expect("invalid script bytes"),
        )
        .push_slice(PushBytesBuf::try_from(p2sh.as_bytes().to_vec()).expect("p2sh bytes"))
        .into_script();
    let tx_recursive = spending_tx(script_sig2);
    assert_verify_matches_core(&p2sh2, &tx_recursive, VERIFY_P2SH)
        .expect("nested p2sh should hash-check inner p2sh and stop recursion");
}

// Mirrors Bitcoin Core src/test/script_p2sh_tests.cpp:switchover.
#[test]
fn core_script_p2sh_tests_switchover_old_vs_new_rules() {
    let redeem_script = Builder::new()
        .push_opcode(all::OP_PUSHNUM_11)
        .push_opcode(all::OP_PUSHNUM_12)
        .push_opcode(all::OP_EQUALVERIFY)
        .into_script();
    let spent_script = ScriptBuf::new_p2sh(&redeem_script.script_hash());
    let tx = spending_tx(push_data_script(redeem_script.as_bytes()));

    assert_verify_matches_core(&spent_script, &tx, VERIFY_NONE)
        .expect("without P2SH rules, scriptSig hash preimage push is accepted");

    let failure = assert_verify_matches_core(&spent_script, &tx, VERIFY_P2SH)
        .expect_err("with P2SH, redeem script executes and must fail EQUALVERIFY");
    assert_eq!(failure.script_error, ScriptError::EqualVerify);
}
