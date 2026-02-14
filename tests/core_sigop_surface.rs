#![cfg(feature = "core-diff")]

use bitcoin::{
    absolute::LockTime,
    blockdata::script::{Builder, PushBytesBuf},
    consensus as btc_consensus,
    hashes::{hash160, sha256, Hash},
    opcodes::all,
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use consensus::{verify_with_flags, VERIFY_P2SH, VERIFY_WITNESS};

fn spend_tx(script_sig: ScriptBuf, witness: Witness) -> Transaction {
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
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

fn assert_surface_parity(script_pubkey: &ScriptBuf, tx: &Transaction, flags: u32, expected_ok: bool) {
    let tx_bytes = btc_consensus::serialize(tx);
    let ours = verify_with_flags(script_pubkey.as_bytes(), 1, &tx_bytes, None, 0, flags);
    let core = bitcoinconsensus::verify_with_flags(script_pubkey.as_bytes(), 1, &tx_bytes, None, 0, flags);
    assert_eq!(
        ours.is_ok(),
        core.is_ok(),
        "surface parity mismatch for flags={flags:#x}\nours={ours:?}\ncore={core:?}"
    );
    assert_eq!(
        ours.is_ok(),
        expected_ok,
        "unexpected result for flags={flags:#x}\nours={ours:?}\ncore={core:?}"
    );
}

#[test]
fn p2wpkh_witness_toggle_matches_core() {
    let script_pubkey = Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(PushBytesBuf::try_from(vec![0x11; 20]).unwrap())
        .into_script();
    let tx = spend_tx(ScriptBuf::new(), Witness::from(vec![vec![], vec![0x02]]));

    assert_surface_parity(&script_pubkey, &tx, VERIFY_P2SH, true);
    assert_surface_parity(&script_pubkey, &tx, VERIFY_P2SH | VERIFY_WITNESS, false);
}

#[test]
fn p2wsh_witness_toggle_matches_core() {
    let witness_script = Builder::new()
        .push_opcode(all::OP_PUSHNUM_1)
        .push_slice(PushBytesBuf::try_from(vec![0x02; 33]).unwrap())
        .push_slice(PushBytesBuf::try_from(vec![0x03; 33]).unwrap())
        .push_opcode(all::OP_PUSHNUM_2)
        .push_opcode(all::OP_CHECKMULTISIGVERIFY)
        .into_script();
    let program = sha256::Hash::hash(witness_script.as_bytes());
    let script_pubkey = Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(PushBytesBuf::try_from(program.to_byte_array().to_vec()).unwrap())
        .into_script();
    let tx = spend_tx(
        ScriptBuf::new(),
        Witness::from(vec![vec![], vec![], witness_script.as_bytes().to_vec()]),
    );

    assert_surface_parity(&script_pubkey, &tx, VERIFY_P2SH, true);
    assert_surface_parity(&script_pubkey, &tx, VERIFY_P2SH | VERIFY_WITNESS, false);
}

#[test]
fn p2sh_p2wsh_witness_toggle_matches_core() {
    let witness_script = Builder::new()
        .push_opcode(all::OP_PUSHNUM_1)
        .push_slice(PushBytesBuf::try_from(vec![0x02; 33]).unwrap())
        .push_slice(PushBytesBuf::try_from(vec![0x03; 33]).unwrap())
        .push_opcode(all::OP_PUSHNUM_2)
        .push_opcode(all::OP_CHECKMULTISIGVERIFY)
        .into_script();
    let witness_program = sha256::Hash::hash(witness_script.as_bytes());
    let redeem_script = Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(PushBytesBuf::try_from(witness_program.to_byte_array().to_vec()).unwrap())
        .into_script();
    let redeem_hash = hash160::Hash::hash(redeem_script.as_bytes());
    let script_pubkey = Builder::new()
        .push_opcode(all::OP_HASH160)
        .push_slice(PushBytesBuf::try_from(redeem_hash.to_byte_array().to_vec()).unwrap())
        .push_opcode(all::OP_EQUAL)
        .into_script();
    let script_sig = Builder::new()
        .push_slice(PushBytesBuf::try_from(redeem_script.as_bytes().to_vec()).unwrap())
        .into_script();
    let tx = spend_tx(
        script_sig,
        Witness::from(vec![vec![], vec![], witness_script.as_bytes().to_vec()]),
    );

    assert_surface_parity(&script_pubkey, &tx, VERIFY_P2SH, true);
    assert_surface_parity(&script_pubkey, &tx, VERIFY_P2SH | VERIFY_WITNESS, false);
}

#[test]
fn witness_v1_program_without_taproot_flag_matches_core() {
    let script_pubkey = Builder::new()
        .push_opcode(all::OP_PUSHNUM_1)
        .push_slice(PushBytesBuf::try_from(vec![0x42; 32]).unwrap())
        .into_script();
    let tx = spend_tx(ScriptBuf::new(), Witness::from(vec![vec![1, 2, 3]]));

    assert_surface_parity(&script_pubkey, &tx, VERIFY_P2SH | VERIFY_WITNESS, true);
}
