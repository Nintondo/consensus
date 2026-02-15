#![cfg(feature = "core-diff")]

mod core_diff_bridge;

use bitcoin::{
    absolute::LockTime,
    blockdata::script::{Builder, Instruction as ScriptInstruction, PushBytesBuf},
    consensus as btc_consensus,
    consensus::Encodable,
    hashes::{hex::FromHex, sha256, Hash, HashEngine},
    key::{TapTweak, UntweakedPublicKey},
    opcodes::all,
    secp256k1::{Parity, Secp256k1},
    taproot::{TapLeafHash, TapNodeHash, TAPROOT_LEAF_TAPSCRIPT},
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use consensus::{
    verify_with_flags_detailed, Utxo, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY,
    VERIFY_CONST_SCRIPTCODE, VERIFY_DERSIG, VERIFY_MINIMALDATA, VERIFY_MINIMALIF, VERIFY_NONE,
    VERIFY_NULLDUMMY, VERIFY_NULLFAIL, VERIFY_P2SH, VERIFY_STRICTENC, VERIFY_TAPROOT,
    VERIFY_WITNESS,
};
use core_diff_bridge::{CoreDiffHarness, CoreUtxo, LEGACY_LIBCONSENSUS_SUPPORTED_FLAGS};
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, TestCaseError, TestRunner};
use std::{cell::RefCell, collections::BTreeMap, env, fmt, slice};

const FLAG_SET: &[u32] = &[
    VERIFY_P2SH,
    VERIFY_DERSIG,
    VERIFY_NULLDUMMY,
    VERIFY_CHECKLOCKTIMEVERIFY,
    VERIFY_CHECKSEQUENCEVERIFY,
    VERIFY_CONST_SCRIPTCODE,
    VERIFY_WITNESS,
    VERIFY_STRICTENC,
    VERIFY_MINIMALDATA,
    VERIFY_MINIMALIF,
    VERIFY_NULLFAIL,
    VERIFY_TAPROOT,
];

struct RandomCase {
    tx_bytes: Vec<u8>,
    script_pubkey: ScriptBuf,
    amount: u64,
    flags: u32,
    prevout: Option<Prevout>,
}

impl fmt::Debug for RandomCase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RandomCase")
            .field("script_pubkey", &self.script_pubkey)
            .field("amount", &self.amount)
            .field("flags", &format_args!("{:#x}", self.flags))
            .finish()
    }
}

struct Prevout {
    ours: Utxo,
    core: CoreUtxo,
}

impl Prevout {
    fn new(script_pubkey: &ScriptBuf, amount: u64) -> Self {
        let ptr = script_pubkey.as_bytes().as_ptr();
        let len = script_pubkey.as_bytes().len() as u32;
        Self {
            ours: Utxo {
                script_pubkey: ptr,
                script_pubkey_len: len,
                value: amount as i64,
            },
            core: CoreUtxo {
                script_pubkey: ptr,
                script_pubkey_len: len,
                value: amount as i64,
            },
        }
    }
}

#[derive(Default)]
struct RandomDiffStats {
    total_cases: usize,
    helper_differential_cases: usize,
    legacy_differential_cases: usize,
    skipped_unsupported_flags: usize,
    skipped_taproot_without_spent_outputs_api: usize,
    skip_reasons: BTreeMap<String, usize>,
}

#[test]
fn random_scripts_match_core_runtime() {
    let strict_helper = env::var("CORE_CPP_DIFF_STRICT").ok().as_deref() == Some("1");
    let runtime = CoreDiffHarness::from_env()
        .unwrap_or_else(|err| panic!("core runtime harness init failed: {err}"));
    let backend_label = runtime
        .as_ref()
        .map(|h| h.backend_label())
        .unwrap_or_else(|| "crate-libbitcoinconsensus".to_string());
    if strict_helper {
        match runtime.as_ref() {
            Some(harness) if harness.is_helper_backend() => {}
            Some(harness) => {
                panic!(
                    "CORE_CPP_DIFF_STRICT=1 requires helper backend for random_consistency, got {}",
                    harness.backend_label()
                );
            }
            None => {
                panic!(
                    "CORE_CPP_DIFF_STRICT=1 requires helper backend for random_consistency; \
                     set CORE_CPP_DIFF_HELPER_BIN or CORE_CPP_DIFF_BUILD_HELPER=1 with BITCOIN_CORE_REPO"
                );
            }
        }
    }

    let runtime = RefCell::new(runtime);
    let stats = RefCell::new(RandomDiffStats::default());
    let mut runner = TestRunner::new(ProptestConfig::with_cases(256));
    let strategy = random_case_strategy();
    runner
        .run(&strategy, |case| {
            let mut runtime_ref = runtime.borrow_mut();
            let mut stats_ref = stats.borrow_mut();
            run_random_case(&case, runtime_ref.as_mut(), &mut stats_ref)
                .map_err(TestCaseError::fail)
        })
        .unwrap_or_else(|err| panic!("random differential case failed: {err}"));

    let stats = stats.into_inner();
    let total_differential = stats.helper_differential_cases + stats.legacy_differential_cases;
    assert!(
        total_differential > 0,
        "random consistency executed no differential checks"
    );

    if strict_helper {
        assert!(
            stats.helper_differential_cases > 0,
            "strict helper profile expected helper-backed random comparisons"
        );
        assert_eq!(
            stats.legacy_differential_cases, 0,
            "strict helper profile must not fall back to legacy differential"
        );
        assert_eq!(
            stats.skipped_unsupported_flags, 0,
            "strict helper profile must not skip unsupported flags"
        );
        assert_eq!(
            stats.skipped_taproot_without_spent_outputs_api, 0,
            "strict helper profile must not skip taproot due missing spent-outputs API"
        );
        assert!(
            stats.skip_reasons.is_empty(),
            "strict helper profile observed skip reasons: {:?}",
            stats.skip_reasons
        );
    }

    println!(
        "random_consistency coverage: backend={} total_cases={} helper_differential={} legacy_differential={} skipped_unsupported={} skipped_taproot_no_spent_outputs={}",
        backend_label,
        stats.total_cases,
        stats.helper_differential_cases,
        stats.legacy_differential_cases,
        stats.skipped_unsupported_flags,
        stats.skipped_taproot_without_spent_outputs_api
    );
    if !stats.skip_reasons.is_empty() {
        println!("random_consistency skips: {:?}", stats.skip_reasons);
    }
}

fn run_random_case(
    case: &RandomCase,
    runtime: Option<&mut CoreDiffHarness>,
    stats: &mut RandomDiffStats,
) -> Result<(), String> {
    stats.total_cases += 1;

    let ours = verify_with_flags_detailed(
        case.script_pubkey.as_bytes(),
        case.amount,
        &case.tx_bytes,
        case.prevout.as_ref().map(|p| slice::from_ref(&p.ours)),
        0,
        case.flags,
    );

    match runtime {
        Some(harness) => {
            let supported_flags = harness.supported_flags_mask();
            if case.flags & !supported_flags != 0 {
                stats.skipped_unsupported_flags += 1;
                *stats
                    .skip_reasons
                    .entry("unsupported_flags_for_backend".to_string())
                    .or_insert(0) += 1;
                return Ok(());
            }
            if !harness.is_helper_backend()
                && case.flags & VERIFY_TAPROOT != 0
                && case.prevout.is_none()
            {
                stats.skipped_unsupported_flags += 1;
                *stats
                    .skip_reasons
                    .entry("legacy_taproot_without_prevout_context".to_string())
                    .or_insert(0) += 1;
                return Ok(());
            }
            if case.flags & VERIFY_TAPROOT != 0 && !harness.has_spent_outputs_api() {
                stats.skipped_taproot_without_spent_outputs_api += 1;
                *stats
                    .skip_reasons
                    .entry("taproot_without_spent_outputs_api".to_string())
                    .or_insert(0) += 1;
                return Ok(());
            }

            let core = harness
                .verify(
                    case.script_pubkey.as_bytes(),
                    case.amount,
                    &case.tx_bytes,
                    case.prevout.as_ref().map(|p| slice::from_ref(&p.core)),
                    0,
                    case.flags,
                )
                .map_err(|err| {
                    format!(
                        "core runtime call failed for random case flags={:#x}: {err}",
                        case.flags
                    )
                })?;

            if harness.is_helper_backend() {
                stats.helper_differential_cases += 1;
            } else {
                stats.legacy_differential_cases += 1;
            }

            if ours.is_ok() != core.ok {
                return Err(format!(
                    "random case diverged\nbackend={}\nscriptPubKey={:?}\nflags={:#x}\nours={ours:?}\ncore_ok={}\ncore_err={}",
                    harness.backend_label(),
                    case.script_pubkey,
                    case.flags,
                    core.ok,
                    core.err_code
                ));
            }
            Ok(())
        }
        None => {
            if case.flags & !LEGACY_LIBCONSENSUS_SUPPORTED_FLAGS != 0 {
                stats.skipped_unsupported_flags += 1;
                *stats
                    .skip_reasons
                    .entry("unsupported_flags_without_runtime_backend".to_string())
                    .or_insert(0) += 1;
                return Ok(());
            }
            if case.flags & VERIFY_TAPROOT != 0 && case.prevout.is_none() {
                stats.skipped_unsupported_flags += 1;
                *stats
                    .skip_reasons
                    .entry("legacy_taproot_without_prevout_context".to_string())
                    .or_insert(0) += 1;
                return Ok(());
            }

            let core_prevout = case.prevout.as_ref().map(|p| bitcoinconsensus::Utxo {
                script_pubkey: p.core.script_pubkey,
                script_pubkey_len: p.core.script_pubkey_len,
                value: p.core.value,
            });
            let core = bitcoinconsensus::verify_with_flags(
                case.script_pubkey.as_bytes(),
                case.amount,
                &case.tx_bytes,
                core_prevout.as_ref().map(slice::from_ref),
                0,
                case.flags,
            );
            stats.legacy_differential_cases += 1;

            if ours.is_ok() != core.is_ok() {
                return Err(format!(
                    "random case diverged\nbackend=crate-libbitcoinconsensus\nscriptPubKey={:?}\nflags={:#x}\nours={ours:?}\ncore={core:?}",
                    case.script_pubkey, case.flags
                ));
            }
            Ok(())
        }
    }
}

fn random_case_strategy() -> impl Strategy<Value = RandomCase> {
    scenario_strategy().prop_flat_map(|scenario| {
        rand_flag_strategy().prop_map(move |flags| scenario.clone().into_case(flags))
    })
}

fn rand_flag_strategy() -> impl Strategy<Value = u32> {
    prop::collection::vec(any::<bool>(), FLAG_SET.len()).prop_map(|bits| {
        let mut flags = VERIFY_NONE;
        for (idx, enabled) in bits.into_iter().enumerate() {
            if enabled {
                flags |= FLAG_SET[idx];
            }
        }
        flags
    })
}

#[derive(Clone, Debug)]
struct Scenario {
    script_sig: ScriptBuf,
    script_pubkey: ScriptBuf,
    witness: Witness,
    amount: u64,
    required_flags: u32,
    needs_prevout: bool,
}

impl Scenario {
    fn into_case(self, random_flags: u32) -> RandomCase {
        let mut flags = random_flags | self.required_flags;
        if flags & VERIFY_WITNESS != 0 {
            flags |= VERIFY_P2SH;
        }
        let tx_bytes = build_spend_transaction(
            &self.script_pubkey,
            &self.script_sig,
            &self.witness,
            self.amount,
        );
        let prevout = if self.needs_prevout {
            Some(Prevout::new(&self.script_pubkey, self.amount))
        } else {
            None
        };
        RandomCase {
            tx_bytes,
            script_pubkey: self.script_pubkey,
            amount: self.amount,
            flags,
            prevout,
        }
    }
}

fn scenario_strategy() -> impl Strategy<Value = Scenario> {
    prop_oneof![
        legacy_basic_scenario(),
        control_flow_scenario(),
        minimal_data_violation_scenario(),
        strictenc_scenario(),
        multisig_scenario(),
        p2sh_scenario(),
        p2wsh_scenario(),
        taproot_scenario(),
    ]
}

fn legacy_basic_scenario() -> impl Strategy<Value = Scenario> {
    (stack_items_strategy(0..4), script_template_strategy()).prop_map(|(stack_items, script)| {
        Scenario {
            script_sig: build_push_script(
                &stack_items
                    .into_iter()
                    .map(|data| (data, PushEncoding::Minimal))
                    .collect::<Vec<_>>(),
            ),
            script_pubkey: script,
            witness: Witness::new(),
            amount: 0,
            required_flags: VERIFY_NONE,
            needs_prevout: false,
        }
    })
}

fn control_flow_scenario() -> impl Strategy<Value = Scenario> {
    (
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        stack_items_strategy(0..2),
        prop::option::of(script_template_strategy()),
    )
        .prop_map(
            |(cond_true, use_else, violate_min_if, stack_items, else_script)| {
                let mut required_flags = VERIFY_NONE;
                let mut builder = Builder::new();
                if violate_min_if {
                    builder =
                        builder.push_slice(PushBytesBuf::try_from(vec![2u8]).expect("push bytes"));
                    required_flags |= VERIFY_MINIMALIF;
                } else {
                    builder = builder.push_int(if cond_true { 1 } else { 0 });
                }
                builder = builder.push_opcode(all::OP_IF);
                builder = builder.push_int(1).push_opcode(all::OP_DROP);
                if use_else {
                    builder = builder.push_opcode(all::OP_ELSE);
                    if let Some(script) = else_script {
                        builder = append_script(builder, &script);
                    } else {
                        builder = builder.push_int(2).push_opcode(all::OP_DROP);
                    }
                }
                builder = builder.push_opcode(all::OP_ENDIF);
                Scenario {
                    script_sig: build_push_script(
                        &stack_items
                            .into_iter()
                            .map(|data| (data, PushEncoding::Minimal))
                            .collect::<Vec<_>>(),
                    ),
                    script_pubkey: builder.into_script(),
                    witness: Witness::new(),
                    amount: 0,
                    required_flags,
                    needs_prevout: false,
                }
            },
        )
}

fn minimal_data_violation_scenario() -> impl Strategy<Value = Scenario> {
    stack_items_strategy(1..3).prop_map(|stack_items| {
        let pushes = stack_items
            .into_iter()
            .map(|data| (data, PushEncoding::NonMinimal))
            .collect::<Vec<_>>();
        let mut builder = Builder::new();
        for _ in 0..pushes.len() {
            builder = builder.push_opcode(all::OP_DROP);
        }
        Scenario {
            script_sig: build_push_script(&pushes),
            script_pubkey: builder.into_script(),
            witness: Witness::new(),
            amount: 0,
            required_flags: VERIFY_MINIMALDATA,
            needs_prevout: false,
        }
    })
}

fn strictenc_scenario() -> impl Strategy<Value = Scenario> {
    (
        signature_bytes_strategy(),
        pubkey_bytes_strategy(),
        any::<bool>(),
    )
        .prop_map(|(sig, pubkey, use_verify)| {
            let mut builder = Builder::new();
            builder = builder.push_slice(PushBytesBuf::try_from(pubkey.clone()).unwrap());
            builder = builder.push_opcode(if use_verify {
                all::OP_CHECKSIGVERIFY
            } else {
                all::OP_CHECKSIG
            });
            let script_sig = build_push_script(&[
                (sig, PushEncoding::Minimal),
                (pubkey, PushEncoding::Minimal),
            ]);
            Scenario {
                script_sig,
                script_pubkey: builder.into_script(),
                witness: Witness::new(),
                amount: 0,
                required_flags: VERIFY_STRICTENC,
                needs_prevout: false,
            }
        })
}

fn multisig_scenario() -> impl Strategy<Value = Scenario> {
    (
        (1u8..=2),
        (2u8..=3),
        prop::collection::vec(signature_bytes_strategy(), 1..=2),
        prop::collection::vec(pubkey_bytes_strategy(), 2..=3),
    )
        .prop_map(|(m_raw, n_raw, signatures, pubkeys)| {
            let n_total = pubkeys.len() as u8;
            let n = n_raw.min(n_total).max(1);
            let m = m_raw.min(n);
            let mut script_builder = Builder::new();
            script_builder = script_builder.push_int(m as i64);
            for pk in &pubkeys {
                script_builder =
                    script_builder.push_slice(PushBytesBuf::try_from(pk.clone()).unwrap());
            }
            script_builder = script_builder.push_int(n as i64);
            script_builder = script_builder.push_opcode(all::OP_CHECKMULTISIG);

            let mut pushes = vec![(vec![0], PushEncoding::Minimal)];
            for sig in signatures {
                pushes.push((sig, PushEncoding::Minimal));
            }
            let script_sig = build_push_script(&pushes);

            Scenario {
                script_sig,
                script_pubkey: script_builder.into_script(),
                witness: Witness::new(),
                amount: 0,
                required_flags: VERIFY_NULLDUMMY | VERIFY_NULLFAIL,
                needs_prevout: false,
            }
        })
}

fn p2sh_scenario() -> impl Strategy<Value = Scenario> {
    (script_template_strategy(), stack_items_strategy(0..3)).prop_map(
        |(redeem_script, stack_items)| {
            let redeem_hash = redeem_script.script_hash();
            let script_pubkey = ScriptBuf::new_p2sh(&redeem_hash);

            let mut pushes = stack_items
                .into_iter()
                .map(|data| (data, PushEncoding::Minimal))
                .collect::<Vec<_>>();
            pushes.push((redeem_script.as_bytes().to_vec(), PushEncoding::Minimal));

            Scenario {
                script_sig: build_push_script(&pushes),
                script_pubkey,
                witness: Witness::new(),
                amount: 0,
                required_flags: VERIFY_P2SH,
                needs_prevout: false,
            }
        },
    )
}

fn p2wsh_scenario() -> impl Strategy<Value = Scenario> {
    (
        script_template_strategy(),
        stack_items_strategy(0..3),
        (1_000u64..10_000_000),
    )
        .prop_map(|(witness_script, stack_items, amount)| {
            let mut witness_items = stack_items;
            witness_items.push(witness_script.as_bytes().to_vec());
            let witness = Witness::from(witness_items);

            let script_hash = sha256::Hash::hash(witness_script.as_bytes());
            let push = PushBytesBuf::try_from(script_hash.to_byte_array().to_vec()).unwrap();
            let script_pubkey = Builder::new()
                .push_opcode(all::OP_PUSHBYTES_0)
                .push_slice(push)
                .into_script();

            Scenario {
                script_sig: ScriptBuf::new(),
                script_pubkey,
                witness,
                amount,
                required_flags: VERIFY_WITNESS,
                needs_prevout: false,
            }
        })
}

fn taproot_scenario() -> impl Strategy<Value = Scenario> {
    (
        script_template_strategy(),
        stack_items_strategy(0..3),
        (1_000u64..10_000_000),
    )
        .prop_map(|(script, stack_items, amount)| {
            let (script_pubkey, witness) = build_taproot_components(script, stack_items);
            Scenario {
                script_sig: ScriptBuf::new(),
                script_pubkey,
                witness,
                amount,
                required_flags: VERIFY_WITNESS | VERIFY_TAPROOT,
                needs_prevout: true,
            }
        })
}

fn script_template_strategy() -> impl Strategy<Value = ScriptBuf> {
    prop_oneof![
        arithmetic_script(),
        equalverify_script(),
        hash_compare_script(),
        num_equal_verify_script(),
    ]
}

fn arithmetic_script() -> impl Strategy<Value = ScriptBuf> {
    ((-1000i64..=1000), (-1000i64..=1000)).prop_map(|(a, b)| {
        let sum = a.saturating_add(b);
        let mut builder = Builder::new();
        builder = builder.push_int(a).push_int(b).push_opcode(all::OP_ADD);
        builder = builder.push_int(sum).push_opcode(all::OP_EQUALVERIFY);
        builder.into_script()
    })
}

fn equalverify_script() -> impl Strategy<Value = ScriptBuf> {
    prop::collection::vec(any::<u8>(), 1..32).prop_map(|data| {
        let mut builder = Builder::new();
        builder = builder
            .push_slice(PushBytesBuf::try_from(data.clone()).unwrap())
            .push_slice(PushBytesBuf::try_from(data).unwrap())
            .push_opcode(all::OP_EQUALVERIFY);
        builder.into_script()
    })
}

fn hash_compare_script() -> impl Strategy<Value = ScriptBuf> {
    prop::collection::vec(any::<u8>(), 1..32).prop_map(|data| {
        let hash = sha256::Hash::hash(&data);
        let mut builder = Builder::new();
        builder = builder
            .push_slice(PushBytesBuf::try_from(data).unwrap())
            .push_opcode(all::OP_SHA256)
            .push_slice(PushBytesBuf::try_from(hash.to_byte_array().to_vec()).unwrap())
            .push_opcode(all::OP_EQUAL);
        builder.into_script()
    })
}

fn num_equal_verify_script() -> impl Strategy<Value = ScriptBuf> {
    ((-1000i64..=1000), (-1000i64..=1000)).prop_map(|(a, b)| {
        let mut builder = Builder::new();
        builder = builder
            .push_int(a)
            .push_int(b)
            .push_opcode(all::OP_NUMEQUALVERIFY);
        builder.into_script()
    })
}

fn stack_items_strategy(len: std::ops::Range<usize>) -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(prop::collection::vec(any::<u8>(), 0..33), len)
}

#[derive(Clone, Copy)]
enum PushEncoding {
    Minimal,
    NonMinimal,
}

fn build_push_script(pushes: &[(Vec<u8>, PushEncoding)]) -> ScriptBuf {
    let mut bytes = Vec::new();
    for (data, encoding) in pushes {
        match encoding {
            PushEncoding::Minimal => encode_minimal_push(&mut bytes, data),
            PushEncoding::NonMinimal => encode_non_minimal_push(&mut bytes, data),
        }
    }
    ScriptBuf::from_bytes(bytes)
}

fn encode_minimal_push(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len == 0 {
        script.push(0x00);
    } else if len <= 75 {
        script.push(len as u8);
    } else if len <= u8::MAX as usize {
        script.push(all::OP_PUSHDATA1.to_u8());
        script.push(len as u8);
    } else if len <= u16::MAX as usize {
        script.push(all::OP_PUSHDATA2.to_u8());
        script.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        script.push(all::OP_PUSHDATA4.to_u8());
        script.extend_from_slice(&(len as u32).to_le_bytes());
    }
    script.extend_from_slice(data);
}

fn encode_non_minimal_push(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u32;
    script.push(all::OP_PUSHDATA4.to_u8());
    script.extend_from_slice(&len.to_le_bytes());
    script.extend_from_slice(data);
}

fn signature_bytes_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 64..80)
}

fn pubkey_bytes_strategy() -> impl Strategy<Value = Vec<u8>> {
    (any::<bool>(), prop::collection::vec(any::<u8>(), 32)).prop_map(|(even, rest)| {
        let mut bytes = Vec::with_capacity(33);
        bytes.push(if even { 0x02 } else { 0x03 });
        bytes.extend(rest);
        bytes
    })
}

fn append_script(mut builder: Builder, script: &ScriptBuf) -> Builder {
    for instruction in script.instructions() {
        match instruction.expect("valid instruction") {
            ScriptInstruction::Op(op) => {
                builder = builder.push_opcode(op);
            }
            ScriptInstruction::PushBytes(bytes) => {
                builder =
                    builder.push_slice(PushBytesBuf::try_from(bytes.as_bytes().to_vec()).unwrap());
            }
        }
    }
    builder
}

fn build_spend_transaction(
    script_pubkey: &ScriptBuf,
    script_sig: &ScriptBuf,
    witness: &Witness,
    amount: u64,
) -> Vec<u8> {
    let credit_tx = Transaction {
        version: bitcoin::transaction::Version(2),
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
    let spending = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prevout,
            script_sig: script_sig.clone(),
            sequence: Sequence::MAX,
            witness: witness.clone(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    btc_consensus::serialize(&spending)
}

fn build_taproot_components(
    script: ScriptBuf,
    mut stack_items: Vec<Vec<u8>>,
) -> (ScriptBuf, Witness) {
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

    stack_items.push(script.as_bytes().to_vec());
    stack_items.push(control);
    let witness = Witness::from(stack_items);

    let program = tweaked.to_x_only_public_key().serialize();
    let program_push = PushBytesBuf::try_from(program.to_vec()).unwrap();
    let script_pubkey = Builder::new()
        .push_opcode(all::OP_PUSHNUM_1)
        .push_slice(program_push)
        .into_script();

    (script_pubkey, witness)
}
