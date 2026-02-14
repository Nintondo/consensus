use bitcoin::{
    absolute::LockTime,
    consensus::{self as btc_consensus, Encodable},
    hashes::{sha256d, Hash},
    opcodes::all,
    sighash::{EcdsaSighashType, SighashCache},
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

const SIGHASH_NONE: u32 = 0x02;
const SIGHASH_SINGLE: u32 = 0x03;
const SIGHASH_ANYONECANPAY: u32 = 0x80;

struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state ^= self.state >> 12;
        self.state ^= self.state << 25;
        self.state ^= self.state >> 27;
        self.state = self.state.wrapping_mul(0x2545_f491_4f6c_dd1d);
        self.state
    }

    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn rand_bool(&mut self) -> bool {
        (self.next_u64() & 1) != 0
    }

    fn randbits(&mut self, bits: u32) -> u32 {
        if bits == 0 {
            0
        } else {
            self.next_u32() & ((1u32 << bits) - 1)
        }
    }

    fn range(&mut self, upper: usize) -> usize {
        assert!(upper > 0);
        (self.next_u64() % upper as u64) as usize
    }
}

fn one_array() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = 1;
    out
}

fn remove_op_codeseparator(script: &ScriptBuf) -> ScriptBuf {
    ScriptBuf::from_bytes(
        script
            .as_bytes()
            .iter()
            .copied()
            .filter(|byte| *byte != all::OP_CODESEPARATOR.to_u8())
            .collect(),
    )
}

fn random_script(rng: &mut DeterministicRng) -> ScriptBuf {
    const OPS: &[u8] = &[
        all::OP_PUSHBYTES_0.to_u8(),
        all::OP_PUSHNUM_1.to_u8(),
        all::OP_PUSHNUM_2.to_u8(),
        all::OP_PUSHNUM_3.to_u8(),
        all::OP_CHECKSIG.to_u8(),
        all::OP_IF.to_u8(),
        all::OP_VERIF.to_u8(),
        all::OP_RETURN.to_u8(),
        all::OP_CODESEPARATOR.to_u8(),
    ];

    let mut bytes = Vec::new();
    let ops = rng.range(10);
    for _ in 0..ops {
        bytes.push(OPS[rng.range(OPS.len())]);
    }
    ScriptBuf::from_bytes(bytes)
}

fn random_txid(rng: &mut DeterministicRng) -> Txid {
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_mut(8) {
        chunk.copy_from_slice(&rng.next_u64().to_le_bytes());
    }
    Txid::from_raw_hash(sha256d::Hash::from_byte_array(bytes))
}

fn random_transaction(rng: &mut DeterministicRng, force_single: bool) -> Transaction {
    let input_count = (rng.randbits(2) + 1) as usize;
    let output_count = if force_single {
        input_count
    } else {
        (rng.randbits(2) + 1) as usize
    };

    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        inputs.push(TxIn {
            previous_output: OutPoint {
                txid: random_txid(rng),
                vout: rng.randbits(2),
            },
            script_sig: random_script(rng),
            sequence: if rng.rand_bool() {
                Sequence::from_consensus(rng.next_u32())
            } else {
                Sequence::MAX
            },
            witness: Witness::new(),
        });
    }

    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        outputs.push(TxOut {
            value: Amount::from_sat(rng.next_u64() % 2_100_000_000_000_000),
            script_pubkey: random_script(rng),
        });
    }

    Transaction {
        version: Version(rng.next_u32() as i32),
        lock_time: if rng.rand_bool() {
            LockTime::from_consensus(rng.next_u32())
        } else {
            LockTime::ZERO
        },
        input: inputs,
        output: outputs,
    }
}

fn append_true(script: &ScriptBuf) -> ScriptBuf {
    let mut bytes = script.as_bytes().to_vec();
    bytes.push(all::OP_PUSHNUM_1.to_u8());
    ScriptBuf::from_bytes(bytes)
}

fn hash_types_for_case(rng: &mut DeterministicRng) -> Vec<u32> {
    let mut hash_types = vec![
        1,
        SIGHASH_SINGLE,
        SIGHASH_NONE,
        1 | SIGHASH_ANYONECANPAY,
        SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
        SIGHASH_NONE | SIGHASH_ANYONECANPAY,
        SIGHASH_ANYONECANPAY,
        0,
        i32::MAX as u32,
    ];
    for i in 0..10 {
        hash_types.push(if i % 2 == 0 {
            (rng.next_u32() as i8) as u32
        } else {
            rng.next_u32()
        });
    }
    hash_types
}

#[derive(Clone, Copy)]
enum ModelSigVersion {
    Base,
    WitnessV0,
}

struct CoreSigHashCacheModel {
    entries: [Option<(ScriptBuf, Vec<u8>)>; 6],
}

impl CoreSigHashCacheModel {
    fn new() -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
        }
    }

    fn cache_index(hash_type: u32) -> usize {
        3 * ((hash_type & SIGHASH_ANYONECANPAY != 0) as usize)
            + 2 * (((hash_type & 0x1f) == SIGHASH_SINGLE) as usize)
            + (((hash_type & 0x1f) == SIGHASH_NONE) as usize)
    }

    fn load(&self, hash_type: u32, script_code: &ScriptBuf) -> Option<&[u8]> {
        let entry = self.entries[Self::cache_index(hash_type)].as_ref()?;
        if entry.0 == *script_code {
            Some(entry.1.as_slice())
        } else {
            None
        }
    }

    fn store(&mut self, hash_type: u32, script_code: &ScriptBuf, prefix: Vec<u8>) {
        self.entries[Self::cache_index(hash_type)] = Some((script_code.clone(), prefix));
    }
}

fn hash_prefix_with_type(prefix: &[u8], hash_type: u32) -> [u8; 32] {
    let mut bytes = prefix.to_vec();
    bytes.extend_from_slice(&hash_type.to_le_bytes());
    sha256d::Hash::hash(&bytes).to_byte_array()
}

fn legacy_signature_prefix(
    script_code: &ScriptBuf,
    tx: &Transaction,
    input_index: usize,
    hash_type: u32,
) -> Option<Vec<u8>> {
    if input_index >= tx.input.len() {
        return Some(one_array().to_vec());
    }

    if (hash_type & 0x1f) == SIGHASH_SINGLE && input_index >= tx.output.len() {
        return None;
    }

    let mut tx_tmp = tx.clone();
    let stripped_script = remove_op_codeseparator(script_code);

    for txin in &mut tx_tmp.input {
        txin.script_sig = ScriptBuf::new();
    }
    tx_tmp.input[input_index].script_sig = stripped_script;

    match hash_type & 0x1f {
        SIGHASH_NONE => {
            tx_tmp.output.clear();
            for (idx, txin) in tx_tmp.input.iter_mut().enumerate() {
                if idx != input_index {
                    txin.sequence = Sequence::ZERO;
                }
            }
        }
        SIGHASH_SINGLE => {
            tx_tmp.output.truncate(input_index + 1);
            for txout in tx_tmp.output.iter_mut().take(input_index) {
                txout.value = Amount::from_sat(u64::MAX);
                txout.script_pubkey = ScriptBuf::new();
            }
            for (idx, txin) in tx_tmp.input.iter_mut().enumerate() {
                if idx != input_index {
                    txin.sequence = Sequence::ZERO;
                }
            }
        }
        _ => {}
    }

    if hash_type & SIGHASH_ANYONECANPAY != 0 {
        tx_tmp.input = vec![tx_tmp.input[input_index].clone()];
    }

    Some(btc_consensus::serialize(&tx_tmp))
}

fn witness_v0_signature_prefix(
    script_code: &ScriptBuf,
    tx: &Transaction,
    input_index: usize,
    amount: Amount,
    hash_type: u32,
) -> Vec<u8> {
    let zero_hash = sha256d::Hash::all_zeros();
    let base_sighash = hash_type & 0x1f;
    let hash_prevouts = if hash_type & SIGHASH_ANYONECANPAY == 0 {
        let mut engine = sha256d::Hash::engine();
        for txin in &tx.input {
            txin.previous_output
                .consensus_encode(&mut engine)
                .expect("hash engine writes are infallible");
        }
        sha256d::Hash::from_engine(engine)
    } else {
        zero_hash
    };
    let hash_sequence = if hash_type & SIGHASH_ANYONECANPAY == 0
        && base_sighash != SIGHASH_SINGLE
        && base_sighash != SIGHASH_NONE
    {
        let mut engine = sha256d::Hash::engine();
        for txin in &tx.input {
            txin.sequence
                .consensus_encode(&mut engine)
                .expect("hash engine writes are infallible");
        }
        sha256d::Hash::from_engine(engine)
    } else {
        zero_hash
    };
    let hash_outputs = if base_sighash != SIGHASH_SINGLE && base_sighash != SIGHASH_NONE {
        let mut engine = sha256d::Hash::engine();
        for txout in &tx.output {
            txout
                .consensus_encode(&mut engine)
                .expect("hash engine writes are infallible");
        }
        sha256d::Hash::from_engine(engine)
    } else if base_sighash == SIGHASH_SINGLE && input_index < tx.output.len() {
        let mut engine = sha256d::Hash::engine();
        tx.output[input_index]
            .consensus_encode(&mut engine)
            .expect("hash engine writes are infallible");
        sha256d::Hash::from_engine(engine)
    } else {
        zero_hash
    };

    let mut prefix = Vec::new();
    tx.version
        .consensus_encode(&mut prefix)
        .expect("vec writes are infallible");
    hash_prevouts
        .consensus_encode(&mut prefix)
        .expect("vec writes are infallible");
    hash_sequence
        .consensus_encode(&mut prefix)
        .expect("vec writes are infallible");
    tx.input[input_index]
        .previous_output
        .consensus_encode(&mut prefix)
        .expect("vec writes are infallible");
    script_code
        .as_script()
        .consensus_encode(&mut prefix)
        .expect("vec writes are infallible");
    amount
        .consensus_encode(&mut prefix)
        .expect("vec writes are infallible");
    tx.input[input_index]
        .sequence
        .consensus_encode(&mut prefix)
        .expect("vec writes are infallible");
    hash_outputs
        .consensus_encode(&mut prefix)
        .expect("vec writes are infallible");
    tx.lock_time
        .consensus_encode(&mut prefix)
        .expect("vec writes are infallible");
    prefix
}

fn signature_hash_model(
    tx: &Transaction,
    input_index: usize,
    script_code: &ScriptBuf,
    amount: Amount,
    hash_type: u32,
    sigversion: ModelSigVersion,
    cache: Option<&mut CoreSigHashCacheModel>,
) -> [u8; 32] {
    let expect_one = matches!(sigversion, ModelSigVersion::Base)
        && (hash_type & 0x1f) == SIGHASH_SINGLE
        && input_index >= tx.output.len();
    if expect_one {
        return one_array();
    }

    if let Some(cache) = cache {
        if let Some(prefix) = cache.load(hash_type, script_code) {
            return hash_prefix_with_type(prefix, hash_type);
        }
        let prefix = match sigversion {
            ModelSigVersion::Base => {
                legacy_signature_prefix(script_code, tx, input_index, hash_type)
                    .expect("legacy SIGHASH_SINGLE bug handled above")
            }
            ModelSigVersion::WitnessV0 => {
                witness_v0_signature_prefix(script_code, tx, input_index, amount, hash_type)
            }
        };
        cache.store(hash_type, script_code, prefix.clone());
        return hash_prefix_with_type(&prefix, hash_type);
    }

    match sigversion {
        ModelSigVersion::Base => {
            let prefix = legacy_signature_prefix(script_code, tx, input_index, hash_type)
                .expect("legacy SIGHASH_SINGLE bug handled above");
            hash_prefix_with_type(&prefix, hash_type)
        }
        ModelSigVersion::WitnessV0 => {
            let prefix =
                witness_v0_signature_prefix(script_code, tx, input_index, amount, hash_type);
            hash_prefix_with_type(&prefix, hash_type)
        }
    }
}

#[test]
fn bitcoin_core_style_sighash_cache_parity() {
    let mut rng = DeterministicRng::new(0x8f23_01bc_4112_d9aa);

    for _ in 0..512 {
        let tx = random_transaction(&mut rng, false);
        let input_index = rng.range(tx.input.len());
        let amount = Amount::from_sat((rng.next_u64() % 50_000_000_000) + 1);

        let script_base = remove_op_codeseparator(&random_script(&mut rng));
        let script_base_diff = append_true(&script_base);
        let script_witness = random_script(&mut rng);
        let script_witness_diff = append_true(&script_witness);

        let hash_types = hash_types_for_case(&mut rng);

        let legacy_cache = SighashCache::new(&tx);
        let mut segwit_cache = SighashCache::new(&tx);

        for hash_type in hash_types {
            // Legacy parity (cache vs no-cache).
            let legacy_with_cache = legacy_cache
                .legacy_signature_hash(input_index, script_base.as_script(), hash_type)
                .expect("legacy sighash with cache")
                .to_byte_array();
            let legacy_no_cache = SighashCache::new(&tx)
                .legacy_signature_hash(input_index, script_base.as_script(), hash_type)
                .expect("legacy sighash without cache")
                .to_byte_array();
            assert_eq!(legacy_with_cache, legacy_no_cache);

            let legacy_repeat = legacy_cache
                .legacy_signature_hash(input_index, script_base.as_script(), hash_type)
                .expect("legacy repeat with cache")
                .to_byte_array();
            assert_eq!(legacy_with_cache, legacy_repeat);

            let legacy_with_cache_diff = legacy_cache
                .legacy_signature_hash(input_index, script_base_diff.as_script(), hash_type)
                .expect("legacy diff script with cache")
                .to_byte_array();
            let legacy_no_cache_diff = SighashCache::new(&tx)
                .legacy_signature_hash(input_index, script_base_diff.as_script(), hash_type)
                .expect("legacy diff script without cache")
                .to_byte_array();
            assert_eq!(legacy_with_cache_diff, legacy_no_cache_diff);

            let expect_one = (hash_type & 0x1f) == SIGHASH_SINGLE && input_index >= tx.output.len();
            if expect_one {
                assert_eq!(legacy_with_cache, one_array());
                assert_eq!(legacy_with_cache_diff, one_array());
            } else {
                assert_ne!(legacy_with_cache, legacy_with_cache_diff);
            }

            let legacy_roundtrip = legacy_cache
                .legacy_signature_hash(input_index, script_base.as_script(), hash_type)
                .expect("legacy script-key roundtrip")
                .to_byte_array();
            assert_eq!(legacy_roundtrip, legacy_with_cache);

            // Witness v0 parity (cache vs no-cache), including hash-type and
            // script-code isolation in a reused cache object.
            let sighash_type = EcdsaSighashType::from_consensus(hash_type);
            let wit_with_cache = segwit_cache
                .p2wsh_signature_hash(
                    input_index,
                    script_witness.as_script(),
                    amount,
                    sighash_type,
                )
                .expect("witness sighash with cache")
                .to_byte_array();
            let wit_no_cache = SighashCache::new(&tx)
                .p2wsh_signature_hash(
                    input_index,
                    script_witness.as_script(),
                    amount,
                    sighash_type,
                )
                .expect("witness sighash without cache")
                .to_byte_array();
            assert_eq!(wit_with_cache, wit_no_cache);

            let wit_repeat = segwit_cache
                .p2wsh_signature_hash(
                    input_index,
                    script_witness.as_script(),
                    amount,
                    sighash_type,
                )
                .expect("witness repeat with cache")
                .to_byte_array();
            assert_eq!(wit_repeat, wit_with_cache);

            let wit_with_cache_diff = segwit_cache
                .p2wsh_signature_hash(
                    input_index,
                    script_witness_diff.as_script(),
                    amount,
                    sighash_type,
                )
                .expect("witness diff script with cache")
                .to_byte_array();
            let wit_no_cache_diff = SighashCache::new(&tx)
                .p2wsh_signature_hash(
                    input_index,
                    script_witness_diff.as_script(),
                    amount,
                    sighash_type,
                )
                .expect("witness diff script without cache")
                .to_byte_array();
            assert_eq!(wit_with_cache_diff, wit_no_cache_diff);
            assert_ne!(wit_with_cache, wit_with_cache_diff);

            let wit_roundtrip = segwit_cache
                .p2wsh_signature_hash(
                    input_index,
                    script_witness.as_script(),
                    amount,
                    sighash_type,
                )
                .expect("witness script-key roundtrip")
                .to_byte_array();
            assert_eq!(wit_roundtrip, wit_with_cache);
        }
    }
}

#[test]
fn bitcoin_core_style_sighash_cache_mutation_model() {
    let mut rng = DeterministicRng::new(0x7b4f_10d1_9a3e_41c2);

    for _ in 0..128 {
        let tx = random_transaction(&mut rng, false);
        let input_index = rng.range(tx.input.len());
        let amount = Amount::from_sat((rng.next_u64() % 50_000_000_000) + 1);
        let script = remove_op_codeseparator(&random_script(&mut rng));
        let diff_script = append_true(&script);

        for sigversion in [ModelSigVersion::Base, ModelSigVersion::WitnessV0] {
            let mut model_cache = CoreSigHashCacheModel::new();
            for hash_type in hash_types_for_case(&mut rng) {
                let effective_hash_type = match sigversion {
                    ModelSigVersion::Base => hash_type,
                    // rust-bitcoin's witness-v0 API takes EcdsaSighashType and
                    // therefore canonicalizes non-standard raw values.
                    ModelSigVersion::WitnessV0 => {
                        EcdsaSighashType::from_consensus(hash_type).to_u32()
                    }
                };
                let model_no_cache = signature_hash_model(
                    &tx,
                    input_index,
                    &script,
                    amount,
                    effective_hash_type,
                    sigversion,
                    None,
                );
                let model_with_cache = signature_hash_model(
                    &tx,
                    input_index,
                    &script,
                    amount,
                    effective_hash_type,
                    sigversion,
                    Some(&mut model_cache),
                );
                assert_eq!(model_with_cache, model_no_cache);

                let rust_hash = match sigversion {
                    ModelSigVersion::Base => SighashCache::new(&tx)
                        .legacy_signature_hash(input_index, script.as_script(), hash_type)
                        .expect("legacy sighash")
                        .to_byte_array(),
                    ModelSigVersion::WitnessV0 => SighashCache::new(&tx)
                        .p2wsh_signature_hash(
                            input_index,
                            script.as_script(),
                            amount,
                            EcdsaSighashType::from_consensus(hash_type),
                        )
                        .expect("witness sighash")
                        .to_byte_array(),
                };
                assert_eq!(
                    model_no_cache,
                    rust_hash,
                    "model mismatch: sigversion={} hash_type={:#x} input_index={} tx_inputs={} tx_outputs={}",
                    match sigversion {
                        ModelSigVersion::Base => "BASE",
                        ModelSigVersion::WitnessV0 => "WITNESS_V0",
                    },
                    effective_hash_type,
                    input_index,
                    tx.input.len(),
                    tx.output.len()
                );

                let expect_one = matches!(sigversion, ModelSigVersion::Base)
                    && (effective_hash_type & 0x1f) == SIGHASH_SINGLE
                    && input_index >= tx.output.len();
                if expect_one {
                    assert_eq!(model_with_cache, one_array());
                    continue;
                }

                // Mirror Core's sighash_caching mutation step: overwrite the
                // cached entry for this hash_type+script and ensure the next
                // call returns the mutated value.
                model_cache.store(effective_hash_type, &script, vec![42u8]);
                let mutated = signature_hash_model(
                    &tx,
                    input_index,
                    &script,
                    amount,
                    effective_hash_type,
                    sigversion,
                    Some(&mut model_cache),
                );
                let expected_mutated = hash_prefix_with_type(&[42u8], effective_hash_type);
                assert_eq!(mutated, expected_mutated);
                assert_ne!(mutated, model_no_cache);

                // Clear the mutated entry and restore the valid cached prefix for
                // the next hash-type iteration, mirroring Core's test flow.
                model_cache.store(effective_hash_type, &diff_script, Vec::new());
                let restored = signature_hash_model(
                    &tx,
                    input_index,
                    &script,
                    amount,
                    effective_hash_type,
                    sigversion,
                    Some(&mut model_cache),
                );
                assert_eq!(restored, model_no_cache);
            }
        }
    }
}
