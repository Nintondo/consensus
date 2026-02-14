use bitcoin::{
    absolute::LockTime,
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
                .p2wsh_signature_hash(input_index, script_witness.as_script(), amount, sighash_type)
                .expect("witness sighash with cache")
                .to_byte_array();
            let wit_no_cache = SighashCache::new(&tx)
                .p2wsh_signature_hash(input_index, script_witness.as_script(), amount, sighash_type)
                .expect("witness sighash without cache")
                .to_byte_array();
            assert_eq!(wit_with_cache, wit_no_cache);

            let wit_repeat = segwit_cache
                .p2wsh_signature_hash(input_index, script_witness.as_script(), amount, sighash_type)
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
                .p2wsh_signature_hash(input_index, script_witness.as_script(), amount, sighash_type)
                .expect("witness script-key roundtrip")
                .to_byte_array();
            assert_eq!(wit_roundtrip, wit_with_cache);
        }
    }
}
