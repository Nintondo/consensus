use bitcoin::{
    absolute::LockTime,
    blockdata::script::{Builder, PushBytesBuf},
    consensus as btc_consensus,
    opcodes::all,
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey},
    sighash::{EcdsaSighashType, SighashCache},
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use consensus::{
    verify_with_flags_detailed, ScriptError, ScriptFailure, VERIFY_P2SH, VERIFY_STRICTENC,
};

const CORE_SCRIPT_TEST_FLAGS: u32 = VERIFY_P2SH | VERIFY_STRICTENC;

fn build_crediting_tx(script_pubkey: &ScriptBuf, value_sat: u64) -> Transaction {
    Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::default(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value_sat),
            script_pubkey: script_pubkey.clone(),
        }],
    }
}

fn build_spending_tx(credit_tx: &Transaction, value_sat: u64) -> Transaction {
    Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: credit_tx.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value_sat),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

fn sign_legacy_multisig_input(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    tx: &Transaction,
    script_pubkey: &ScriptBuf,
    keys: &[SecretKey],
) -> ScriptBuf {
    let mut script_sig = Builder::new().push_opcode(all::OP_PUSHBYTES_0);
    for key in keys {
        let cache = SighashCache::new(tx);
        let sighash = cache
            .legacy_signature_hash(0, script_pubkey, EcdsaSighashType::All.to_u32())
            .expect("legacy sighash");
        let msg = Message::from_digest_slice(&sighash[..]).expect("sighash to message");
        let sig = secp.sign_ecdsa(&msg, key);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(EcdsaSighashType::All.to_u32() as u8);
        script_sig = script_sig.push_slice(
            PushBytesBuf::try_from(sig_bytes).expect("signature push bytes conversion"),
        );
    }
    script_sig.into_script()
}

fn assert_verify_matches_core(
    spent_script: &ScriptBuf,
    amount_sat: u64,
    tx: &Transaction,
    flags: u32,
) -> Result<(), ScriptFailure> {
    let tx_bytes = btc_consensus::serialize(tx);
    let ours = verify_with_flags_detailed(spent_script.as_bytes(), amount_sat, &tx_bytes, None, 0, flags);

    #[cfg(feature = "core-diff")]
    {
        const LIBCONSENSUS_SUPPORTED_FLAGS: u32 = consensus::VERIFY_P2SH
            | consensus::VERIFY_DERSIG
            | consensus::VERIFY_NULLDUMMY
            | consensus::VERIFY_CHECKLOCKTIMEVERIFY
            | consensus::VERIFY_CHECKSEQUENCEVERIFY
            | consensus::VERIFY_WITNESS
            | consensus::VERIFY_TAPROOT;
        let diff_flags = flags & LIBCONSENSUS_SUPPORTED_FLAGS;
        let ours_diff = if diff_flags == flags {
            ours.is_ok()
        } else {
            verify_with_flags_detailed(spent_script.as_bytes(), amount_sat, &tx_bytes, None, 0, diff_flags)
                .is_ok()
        };
        let core = bitcoinconsensus::verify_with_flags(
            spent_script.as_bytes(),
            amount_sat,
            &tx_bytes,
            None,
            0,
            diff_flags,
        );
        assert_eq!(
            ours_diff,
            core.is_ok(),
            "Core mismatch for CHECKMULTISIG parity test: flags={flags:#x} diff_flags={diff_flags:#x} ours={ours:?} core={core:?}"
        );
    }

    ours
}

// Mirrors Bitcoin Core src/test/script_tests.cpp:script_CHECKMULTISIG12.
#[test]
fn core_script_tests_script_checkmultisig12_parity() {
    let secp = Secp256k1::new();
    let key1 = SecretKey::from_slice(&[1u8; 32]).expect("key1");
    let key2 = SecretKey::from_slice(&[2u8; 32]).expect("key2");
    let key3 = SecretKey::from_slice(&[3u8; 32]).expect("key3");

    let pk1 = PublicKey::from_secret_key(&secp, &key1);
    let pk2 = PublicKey::from_secret_key(&secp, &key2);

    let script_pubkey = Builder::new()
        .push_opcode(all::OP_PUSHNUM_1)
        .push_slice(PushBytesBuf::try_from(pk1.serialize().to_vec()).expect("pk1 push bytes"))
        .push_slice(
            PushBytesBuf::try_from(pk2.serialize_uncompressed().to_vec()).expect("pk2 push bytes"),
        )
        .push_opcode(all::OP_PUSHNUM_2)
        .push_opcode(all::OP_CHECKMULTISIG)
        .into_script();

    let tx_from = build_crediting_tx(&script_pubkey, 1);
    let mut tx_to = build_spending_tx(&tx_from, 1);

    let goodsig1 = sign_legacy_multisig_input(&secp, &tx_to, &script_pubkey, &[key1]);
    tx_to.input[0].script_sig = goodsig1;
    assert_verify_matches_core(
        &script_pubkey,
        tx_from.output[0].value.to_sat(),
        &tx_to,
        CORE_SCRIPT_TEST_FLAGS,
    )
    .expect("key1 signature should satisfy 1-of-2 multisig");

    tx_to.output[0].value = Amount::from_sat(2);
    assert!(
        assert_verify_matches_core(
            &script_pubkey,
            tx_from.output[0].value.to_sat(),
            &tx_to,
            CORE_SCRIPT_TEST_FLAGS,
        )
        .is_err(),
        "changing outputs should invalidate existing signature"
    );

    let goodsig2 = sign_legacy_multisig_input(&secp, &tx_to, &script_pubkey, &[key2]);
    tx_to.input[0].script_sig = goodsig2;
    assert_verify_matches_core(
        &script_pubkey,
        tx_from.output[0].value.to_sat(),
        &tx_to,
        CORE_SCRIPT_TEST_FLAGS,
    )
    .expect("key2 signature should satisfy 1-of-2 multisig");

    let badsig1 = sign_legacy_multisig_input(&secp, &tx_to, &script_pubkey, &[key3]);
    tx_to.input[0].script_sig = badsig1;
    let bad = assert_verify_matches_core(
        &script_pubkey,
        tx_from.output[0].value.to_sat(),
        &tx_to,
        CORE_SCRIPT_TEST_FLAGS,
    )
    .expect_err("unrelated key signature must fail");
    assert_eq!(bad.script_error, ScriptError::EvalFalse);
}

// Mirrors Bitcoin Core src/test/script_tests.cpp:script_CHECKMULTISIG23.
#[test]
fn core_script_tests_script_checkmultisig23_parity() {
    let secp = Secp256k1::new();
    let key1 = SecretKey::from_slice(&[11u8; 32]).expect("key1");
    let key2 = SecretKey::from_slice(&[12u8; 32]).expect("key2");
    let key3 = SecretKey::from_slice(&[13u8; 32]).expect("key3");
    let key4 = SecretKey::from_slice(&[14u8; 32]).expect("key4");

    let pk1 = PublicKey::from_secret_key(&secp, &key1);
    let pk2 = PublicKey::from_secret_key(&secp, &key2);
    let pk3 = PublicKey::from_secret_key(&secp, &key3);

    let script_pubkey = Builder::new()
        .push_opcode(all::OP_PUSHNUM_2)
        .push_slice(PushBytesBuf::try_from(pk1.serialize().to_vec()).expect("pk1 push bytes"))
        .push_slice(
            PushBytesBuf::try_from(pk2.serialize_uncompressed().to_vec()).expect("pk2 push bytes"),
        )
        .push_slice(PushBytesBuf::try_from(pk3.serialize().to_vec()).expect("pk3 push bytes"))
        .push_opcode(all::OP_PUSHNUM_3)
        .push_opcode(all::OP_CHECKMULTISIG)
        .into_script();

    let tx_from = build_crediting_tx(&script_pubkey, 1);
    let mut tx_to = build_spending_tx(&tx_from, 1);
    let amount_sat = tx_from.output[0].value.to_sat();

    for keys in [
        vec![key1, key2],
        vec![key1, key3],
        vec![key2, key3],
    ] {
        tx_to.input[0].script_sig = sign_legacy_multisig_input(&secp, &tx_to, &script_pubkey, &keys);
        assert_verify_matches_core(&script_pubkey, amount_sat, &tx_to, CORE_SCRIPT_TEST_FLAGS)
            .expect("valid 2-of-3 signature pair should pass");
    }

    for keys in [
        vec![key2, key2], // duplicate signature cannot satisfy two pubkeys
        vec![key2, key1], // wrong order
        vec![key3, key2], // wrong order
        vec![key4, key2], // key mismatch
        vec![key1, key4], // key mismatch
    ] {
        tx_to.input[0].script_sig = sign_legacy_multisig_input(&secp, &tx_to, &script_pubkey, &keys);
        let failure = assert_verify_matches_core(&script_pubkey, amount_sat, &tx_to, CORE_SCRIPT_TEST_FLAGS)
            .expect_err("invalid signature set should fail");
        assert_eq!(failure.script_error, ScriptError::EvalFalse);
    }

    tx_to.input[0].script_sig = sign_legacy_multisig_input(&secp, &tx_to, &script_pubkey, &[]);
    let no_sigs = assert_verify_matches_core(&script_pubkey, amount_sat, &tx_to, CORE_SCRIPT_TEST_FLAGS)
        .expect_err("empty signature set should fail with stack underflow");
    assert_eq!(no_sigs.script_error, ScriptError::InvalidStackOperation);
}
