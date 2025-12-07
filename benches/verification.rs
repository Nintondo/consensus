use bitcoin::{
    absolute::LockTime,
    blockdata::script::{Builder, PushBytesBuf},
    consensus::{self as btc_consensus, Encodable},
    hashes::{hex::FromHex, sha256, Hash, HashEngine},
    key::{Secp256k1, TapTweak, UntweakedPublicKey},
    opcodes::all,
    secp256k1::Parity,
    taproot::{TapLeafHash, TapNodeHash, TAPROOT_LEAF_TAPSCRIPT},
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use consensus::{verify_with_flags, Utxo, VERIFY_ALL_PRE_TAPROOT, VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS};

#[cfg(feature = "core-diff")]
use bitcoinconsensus;

struct BenchCase {
    name: &'static str,
    script_pubkey: Vec<u8>,
    amount: u64,
    tx_bytes: Vec<u8>,
    prevouts: Option<Vec<Prevout>>,
    flags: u32,
}

struct Prevout {
    script_pubkey: Vec<u8>,
    amount: u64,
}

pub fn verification_bench(c: &mut Criterion) {
    let cases = vec![
        legacy_p2pkh_case(),
        simple_p2sh_case(),
        simple_p2wsh_case(),
        taproot_script_case(),
    ];

    let mut group = c.benchmark_group("verify");
    for case in cases {
        group.bench_with_input(BenchmarkId::new("rust", case.name), &case, |b, case| {
            b.iter(|| run_case_rust(case));
        });

        #[cfg(feature = "core-diff")]
        group.bench_with_input(
            BenchmarkId::new("libbitcoinconsensus", case.name),
            &case,
            |b, case| {
                b.iter(|| run_case_core(case));
            },
        );
    }
    group.finish();
}

fn run_case_rust(case: &BenchCase) {
    let prevouts = case.prevouts.as_ref().map(|p| build_prevouts(p));
    verify_with_flags(
        case.script_pubkey.as_slice(),
        case.amount,
        &case.tx_bytes,
        prevouts.as_deref(),
        0,
        case.flags,
    )
    .expect("rust verification");
}

#[cfg(feature = "core-diff")]
fn run_case_core(case: &BenchCase) {
    let prevouts = case
        .prevouts
        .as_ref()
        .map(|p| build_core_prevouts(p));
    bitcoinconsensus::verify_with_flags(
        case.script_pubkey.as_slice(),
        case.amount,
        &case.tx_bytes,
        prevouts.as_deref(),
        0,
        case.flags,
    )
    .expect("core verification");
}

fn legacy_p2pkh_case() -> BenchCase {
    let spent = Vec::from_hex("76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac").unwrap();
    let spending = Vec::from_hex("02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700").unwrap();
    BenchCase {
        name: "legacy_p2pkh",
        script_pubkey: spent,
        amount: 0,
        tx_bytes: spending,
        prevouts: None,
        flags: VERIFY_ALL_PRE_TAPROOT,
    }
}

fn simple_p2sh_case() -> BenchCase {
    let redeem_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
    let script_pubkey = ScriptBuf::new_p2sh(&redeem_script.script_hash());
    let script_sig = push_data_script(redeem_script.as_bytes());

    let tx = Transaction {
        version: bitcoin::transaction::Version(2),
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
    };

    BenchCase {
        name: "p2sh_redeem",
        script_pubkey: script_pubkey.as_bytes().to_vec(),
        amount: 0,
        tx_bytes: btc_consensus::serialize(&tx),
        prevouts: None,
        flags: VERIFY_P2SH,
    }
}

fn simple_p2wsh_case() -> BenchCase {
    let witness_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
    let script_hash = sha256::Hash::hash(witness_script.as_bytes());
    let push = PushBytesBuf::try_from(script_hash.to_byte_array().to_vec()).unwrap();
    let script_pubkey = Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(push)
        .into_script();

    let witness = Witness::from(vec![witness_script.into_bytes()]);
    let tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::default(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: witness.clone(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::new(),
        }],
    };

    BenchCase {
        name: "p2wsh",
        script_pubkey: script_pubkey.as_bytes().to_vec(),
        amount: 50_000,
        tx_bytes: btc_consensus::serialize(&tx),
        prevouts: Some(vec![Prevout {
            script_pubkey: script_pubkey.as_bytes().to_vec(),
            amount: 50_000,
        }]),
        flags: VERIFY_WITNESS | VERIFY_P2SH,
    }
}

fn taproot_script_case() -> BenchCase {
    let script = Builder::new()
        .push_int(1)
        .push_int(1)
        .push_opcode(all::OP_ADD)
        .push_int(2)
        .push_opcode(all::OP_EQUAL)
        .into_script();
    let (script_pubkey, witness) = taproot_script_fixture(script.clone(), &[]);
    let tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::default(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::new(),
        }],
    };

    BenchCase {
        name: "taproot_script",
        script_pubkey: script_pubkey.as_bytes().to_vec(),
        amount: 75_000,
        tx_bytes: btc_consensus::serialize(&tx),
        prevouts: Some(vec![Prevout {
            script_pubkey: script_pubkey.as_bytes().to_vec(),
            amount: 75_000,
        }]),
        flags: VERIFY_WITNESS | VERIFY_P2SH | VERIFY_TAPROOT,
    }
}

fn taproot_script_fixture(script: ScriptBuf, stack_items: &[Vec<u8>]) -> (ScriptBuf, Witness) {
    let internal_key_bytes =
        Vec::from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .expect("generator x");
    let internal_key = UntweakedPublicKey::from_slice(&internal_key_bytes).unwrap();
    let secp = Secp256k1::verification_only();

    let mut engine = TapLeafHash::engine();
    engine.input(&[TAPROOT_LEAF_TAPSCRIPT]);
    script
        .consensus_encode(&mut engine)
        .expect("script serialize");
    let tapleaf_hash = TapLeafHash::from_engine(engine);
    let merkle_root = TapNodeHash::from(tapleaf_hash);
    let (tweaked, parity) = internal_key.tap_tweak(&secp, Some(merkle_root));
    let parity_bit = match parity {
        Parity::Even => 0,
        Parity::Odd => 1,
    };

    let mut control = Vec::with_capacity(33);
    control.push(TAPROOT_LEAF_TAPSCRIPT | parity_bit);
    control.extend_from_slice(&internal_key.serialize());

    let mut witness_items: Vec<Vec<u8>> = stack_items.to_vec();
    witness_items.push(script.as_bytes().to_vec());
    witness_items.push(control);
    let witness = Witness::from(witness_items);

    let program = tweaked.to_x_only_public_key().serialize();
    let program_push = PushBytesBuf::try_from(program.to_vec()).unwrap();
    let script_pubkey = Builder::new()
        .push_opcode(all::OP_PUSHNUM_1)
        .push_slice(program_push)
        .into_script();

    (script_pubkey, witness)
}

fn push_data_script(data: &[u8]) -> ScriptBuf {
    let push = PushBytesBuf::try_from(data.to_vec()).unwrap();
    Builder::new().push_slice(push).into_script()
}

fn build_prevouts(prevouts: &[Prevout]) -> Vec<Utxo> {
    prevouts
        .iter()
        .map(|p| Utxo {
            script_pubkey: p.script_pubkey.as_ptr(),
            script_pubkey_len: p.script_pubkey.len() as u32,
            value: p.amount as i64,
        })
        .collect()
}

#[cfg(feature = "core-diff")]
fn build_core_prevouts(prevouts: &[Prevout]) -> Vec<bitcoinconsensus::Utxo> {
    prevouts
        .iter()
        .map(|p| bitcoinconsensus::Utxo {
            script_pubkey: p.script_pubkey.as_ptr(),
            script_pubkey_len: p.script_pubkey.len() as u32,
            value: p.amount as i64,
        })
        .collect()
}

criterion_group!(benches, verification_bench);
criterion_main!(benches);
