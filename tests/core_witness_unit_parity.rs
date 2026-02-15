use bitcoin::{
    absolute::LockTime,
    blockdata::script::{Builder, PushBytesBuf},
    consensus as btc_consensus,
    hashes::{hash160, hash160::Hash as Hash160, Hash},
    opcodes::all,
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey},
    sighash::{EcdsaSighashType, SegwitV0Sighash, SighashCache},
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use consensus::{
    verify_with_flags_detailed, ScriptError, ScriptFailure, VERIFY_NONE, VERIFY_P2SH,
    VERIFY_WITNESS,
};

fn spending_tx(script_sig: ScriptBuf, witness: Witness, value_sat: u64) -> Transaction {
    Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::default(),
            script_sig,
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value_sat),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

fn p2wpkh_script(pubkey: &PublicKey) -> ScriptBuf {
    let program = Hash160::hash(&pubkey.serialize());
    Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(
            PushBytesBuf::try_from(program.to_byte_array().to_vec()).expect("program bytes"),
        )
        .into_script()
}

fn p2wpkh_script_code(pubkey: &PublicKey) -> ScriptBuf {
    let program = hash160::Hash::hash(&pubkey.serialize());
    Builder::new()
        .push_opcode(all::OP_DUP)
        .push_opcode(all::OP_HASH160)
        .push_slice(
            PushBytesBuf::try_from(program.to_byte_array().to_vec()).expect("hash160 bytes"),
        )
        .push_opcode(all::OP_EQUALVERIFY)
        .push_opcode(all::OP_CHECKSIG)
        .into_script()
}

fn sign_p2wpkh_input(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    tx: &Transaction,
    pubkey: &PublicKey,
    amount_sat: u64,
    key: &SecretKey,
) -> Vec<u8> {
    let script_code = p2wpkh_script_code(pubkey);
    let mut cache = SighashCache::new(tx);
    let mut engine = SegwitV0Sighash::engine();
    cache
        .segwit_v0_encode_signing_data_to(
            &mut engine,
            0,
            &script_code,
            Amount::from_sat(amount_sat),
            EcdsaSighashType::All,
        )
        .expect("segwit sighash");
    let sighash = SegwitV0Sighash::from_engine(engine);
    let msg = Message::from_digest_slice(&sighash[..]).expect("sighash to message");
    let sig = secp.sign_ecdsa(&msg, key);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All.to_u32() as u8);
    sig_bytes
}

fn sign_legacy_input(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    tx: &Transaction,
    script_code: &ScriptBuf,
    key: &SecretKey,
) -> Vec<u8> {
    let cache = SighashCache::new(tx);
    let sighash = cache
        .legacy_signature_hash(0, script_code, EcdsaSighashType::All.to_u32())
        .expect("legacy sighash");
    let msg = Message::from_digest_slice(&sighash[..]).expect("sighash to message");
    let sig = secp.sign_ecdsa(&msg, key);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All.to_u32() as u8);
    sig_bytes
}

fn assert_verify_matches_core(
    spent_script: &ScriptBuf,
    amount_sat: u64,
    tx: &Transaction,
    flags: u32,
    expect_ok: bool,
) -> Result<(), ScriptFailure> {
    let tx_bytes = btc_consensus::serialize(tx);
    let ours = verify_with_flags_detailed(
        spent_script.as_bytes(),
        amount_sat,
        &tx_bytes,
        None,
        0,
        flags,
    );

    #[cfg(feature = "core-diff")]
    {
        let core = bitcoinconsensus::verify_with_flags(
            spent_script.as_bytes(),
            amount_sat,
            &tx_bytes,
            None,
            0,
            flags,
        );
        assert_eq!(
            ours.is_ok(),
            core.is_ok(),
            "Core mismatch for witness parity test: flags={flags:#x} ours={ours:?} core={core:?}"
        );
    }

    assert_eq!(
        ours.is_ok(),
        expect_ok,
        "unexpected local result for witness parity test: flags={flags:#x} ours={ours:?}"
    );
    ours
}

fn push_data_script(data: &[u8]) -> ScriptBuf {
    Builder::new()
        .push_slice(PushBytesBuf::try_from(data.to_vec()).expect("push-data bytes"))
        .into_script()
}

// Mirrors the witness-key matrix in Bitcoin Core src/test/transaction_tests.cpp:test_witness.
#[test]
fn core_transaction_tests_test_witness_native_p2wpkh_matrix() {
    let secp = Secp256k1::new();
    let key1 = SecretKey::from_slice(&[31u8; 32]).expect("key1");
    let key2 = SecretKey::from_slice(&[32u8; 32]).expect("key2");
    let pubkey1 = PublicKey::from_secret_key(&secp, &key1);
    let pubkey2 = PublicKey::from_secret_key(&secp, &key2);
    let amount_sat = 50_000;
    let spent_script = p2wpkh_script(&pubkey1);

    let mut tx_good = spending_tx(ScriptBuf::new(), Witness::new(), amount_sat);
    let sig_good = sign_p2wpkh_input(&secp, &tx_good, &pubkey1, amount_sat, &key1);
    tx_good.input[0].witness = Witness::from(vec![sig_good, pubkey1.serialize().to_vec()]);

    let mut tx_bad = spending_tx(ScriptBuf::new(), Witness::new(), amount_sat);
    let sig_bad = sign_p2wpkh_input(&secp, &tx_bad, &pubkey2, amount_sat, &key2);
    tx_bad.input[0].witness = Witness::from(vec![sig_bad, pubkey2.serialize().to_vec()]);

    for flags in [VERIFY_NONE, VERIFY_P2SH, VERIFY_P2SH | VERIFY_WITNESS] {
        assert_verify_matches_core(&spent_script, amount_sat, &tx_good, flags, true)
            .expect("good native p2wpkh spend should pass");
    }
    assert_verify_matches_core(&spent_script, amount_sat, &tx_bad, VERIFY_NONE, true)
        .expect("witness is ignored without VERIFY_WITNESS");
    assert_verify_matches_core(&spent_script, amount_sat, &tx_bad, VERIFY_P2SH, true)
        .expect("witness is ignored without VERIFY_WITNESS");
    let bad = assert_verify_matches_core(
        &spent_script,
        amount_sat,
        &tx_bad,
        VERIFY_P2SH | VERIFY_WITNESS,
        false,
    )
    .expect_err("wrong-key witness should fail when witness validation is active");
    assert_eq!(bad.script_error, ScriptError::EqualVerify);
}

// Mirrors P2SH-wrapped witness behavior in src/test/transaction_tests.cpp:test_witness.
#[test]
fn core_transaction_tests_test_witness_p2sh_p2wpkh_wrong_witness_and_wrong_redeem() {
    let secp = Secp256k1::new();
    let key1 = SecretKey::from_slice(&[41u8; 32]).expect("key1");
    let key2 = SecretKey::from_slice(&[42u8; 32]).expect("key2");
    let pubkey1 = PublicKey::from_secret_key(&secp, &key1);
    let pubkey2 = PublicKey::from_secret_key(&secp, &key2);
    let amount_sat = 50_000;

    let redeem_script = p2wpkh_script(&pubkey1);
    let spent_script = ScriptBuf::new_p2sh(&redeem_script.script_hash());

    let mut tx_good = spending_tx(
        push_data_script(redeem_script.as_bytes()),
        Witness::new(),
        amount_sat,
    );
    let sig_good = sign_p2wpkh_input(&secp, &tx_good, &pubkey1, amount_sat, &key1);
    tx_good.input[0].witness = Witness::from(vec![sig_good, pubkey1.serialize().to_vec()]);

    let mut tx_wrong_witness = spending_tx(
        push_data_script(redeem_script.as_bytes()),
        Witness::new(),
        amount_sat,
    );
    let sig_wrong_witness =
        sign_p2wpkh_input(&secp, &tx_wrong_witness, &pubkey2, amount_sat, &key2);
    tx_wrong_witness.input[0].witness =
        Witness::from(vec![sig_wrong_witness, pubkey2.serialize().to_vec()]);

    for flags in [VERIFY_NONE, VERIFY_P2SH, VERIFY_P2SH | VERIFY_WITNESS] {
        assert_verify_matches_core(&spent_script, amount_sat, &tx_good, flags, true)
            .expect("good p2sh-p2wpkh spend should pass");
    }
    assert_verify_matches_core(
        &spent_script,
        amount_sat,
        &tx_wrong_witness,
        VERIFY_NONE,
        true,
    )
    .expect("without witness verification, wrong witness stack is ignored");
    assert_verify_matches_core(
        &spent_script,
        amount_sat,
        &tx_wrong_witness,
        VERIFY_P2SH,
        true,
    )
    .expect("without witness verification, wrong witness stack is ignored");
    assert_verify_matches_core(
        &spent_script,
        amount_sat,
        &tx_wrong_witness,
        VERIFY_P2SH | VERIFY_WITNESS,
        false,
    )
    .expect_err("wrong witness must fail when witness verification is active");

    // Wrong-redeem variant mirroring P2SH behavior in test_witness:
    // without P2SH the redeem script is not executed, with P2SH it is.
    let redeem_script_target = Builder::new()
        .push_slice(PushBytesBuf::try_from(pubkey1.serialize().to_vec()).expect("pubkey1 bytes"))
        .push_opcode(all::OP_CHECKSIG)
        .into_script();
    let redeem_script_other = Builder::new()
        .push_slice(PushBytesBuf::try_from(pubkey2.serialize().to_vec()).expect("pubkey2 bytes"))
        .push_opcode(all::OP_CHECKSIG)
        .into_script();
    let mut tx_wrong_redeem = spending_tx(ScriptBuf::new(), Witness::new(), amount_sat);
    let sig_for_other = sign_legacy_input(&secp, &tx_wrong_redeem, &redeem_script_other, &key2);
    tx_wrong_redeem.input[0].script_sig = Builder::new()
        .push_slice(PushBytesBuf::try_from(sig_for_other).expect("signature bytes"))
        .push_slice(
            PushBytesBuf::try_from(redeem_script_target.as_bytes().to_vec())
                .expect("redeem script bytes"),
        )
        .into_script();

    let spent_script_legacy = ScriptBuf::new_p2sh(&redeem_script_target.script_hash());
    assert_verify_matches_core(
        &spent_script_legacy,
        amount_sat,
        &tx_wrong_redeem,
        VERIFY_NONE,
        true,
    )
    .expect("without P2SH, redeem execution is skipped");
    let wrong_redeem = assert_verify_matches_core(
        &spent_script_legacy,
        amount_sat,
        &tx_wrong_redeem,
        VERIFY_P2SH,
        false,
    )
    .expect_err("with P2SH, wrong redeem/signature pairing must fail");
    assert_eq!(wrong_redeem.script_error, ScriptError::EvalFalse);
}

// Mirrors wrapped-witness detection behavior from src/test/transaction_tests.cpp:spends_witness_prog.
#[test]
fn core_transaction_tests_spends_witness_prog_wrapped_witness_detection_surface() {
    let witness_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
    let witness_program = bitcoin::hashes::sha256::Hash::hash(witness_script.as_bytes());
    let redeem_script = Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(
            PushBytesBuf::try_from(witness_program.to_byte_array().to_vec())
                .expect("program bytes"),
        )
        .into_script();
    let spent_script = ScriptBuf::new_p2sh(&redeem_script.script_hash());
    let amount_sat = 1_000;

    // Wrapped witness program is detected only when the redeem script is provided in scriptSig.
    let tx_with_redeem = spending_tx(
        push_data_script(redeem_script.as_bytes()),
        Witness::new(),
        amount_sat,
    );
    let with_redeem = assert_verify_matches_core(
        &spent_script,
        amount_sat,
        &tx_with_redeem,
        VERIFY_P2SH | VERIFY_WITNESS,
        false,
    )
    .expect_err("wrapped witness spends require witness stack");
    assert_eq!(
        with_redeem.script_error,
        ScriptError::WitnessProgramWitnessEmpty
    );

    let tx_without_redeem = spending_tx(ScriptBuf::new(), Witness::new(), amount_sat);
    let without_redeem = assert_verify_matches_core(
        &spent_script,
        amount_sat,
        &tx_without_redeem,
        VERIFY_P2SH | VERIFY_WITNESS,
        false,
    )
    .expect_err("without redeem script there is no wrapped witness dispatch");
    assert_eq!(
        without_redeem.script_error,
        ScriptError::InvalidStackOperation
    );
}
