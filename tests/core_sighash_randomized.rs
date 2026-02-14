use bitcoin::{
    absolute::LockTime,
    consensus as btc_consensus,
    hashes::{sha256d, Hash},
    opcodes::all,
    script::{Instruction, ScriptBuf},
    sighash::SighashCache,
    transaction::Version,
    Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

const SIGHASH_NONE: u32 = 0x02;
const SIGHASH_SINGLE: u32 = 0x03;
const SIGHASH_ANYONECANPAY: u32 = 0x80;
const RANDOM_TESTS: usize = 20_000;

#[derive(Clone)]
struct DeterministicRng(u64);

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn rand_bool(&mut self) -> bool {
        self.next_u32() & 1 == 1
    }

    fn randbits(&mut self, bits: u32) -> u32 {
        if bits == 32 {
            self.next_u32()
        } else {
            self.next_u32() & ((1u32 << bits) - 1)
        }
    }

    fn range(&mut self, upper: usize) -> usize {
        assert!(upper > 0, "upper bound must be positive");
        (self.next_u64() as usize) % upper
    }
}

fn to_one_hash() -> sha256d::Hash {
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    sha256d::Hash::from_byte_array(bytes)
}

fn remove_op_codeseparator(script: &ScriptBuf) -> ScriptBuf {
    let bytes = script.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut cursor = 0usize;
    for item in script.instruction_indices() {
        let (index, instruction) = item.expect("random scripts are valid opcode streams");
        if let Instruction::Op(op) = instruction {
            if op == all::OP_CODESEPARATOR {
                out.extend_from_slice(&bytes[cursor..index]);
                cursor = index + 1;
            }
        }
    }
    out.extend_from_slice(&bytes[cursor..]);
    ScriptBuf::from_bytes(out)
}

fn legacy_signature_hash_old(
    script_code: &ScriptBuf,
    tx: &Transaction,
    input_index: usize,
    hash_type: u32,
) -> sha256d::Hash {
    if input_index >= tx.input.len() {
        return to_one_hash();
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
            if input_index >= tx_tmp.output.len() {
                return to_one_hash();
            }
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

    let mut encoded = btc_consensus::serialize(&tx_tmp);
    encoded.extend_from_slice(&hash_type.to_le_bytes());
    sha256d::Hash::hash(&encoded)
}

fn random_script(rng: &mut DeterministicRng) -> ScriptBuf {
    let opcodes: &[u8] = &[
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
    let ops = rng.range(10);
    let mut bytes = Vec::with_capacity(ops);
    for _ in 0..ops {
        bytes.push(opcodes[rng.range(opcodes.len())]);
    }
    ScriptBuf::from_bytes(bytes)
}

fn random_txid(rng: &mut DeterministicRng) -> Txid {
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_exact_mut(8) {
        chunk.copy_from_slice(&rng.next_u64().to_le_bytes());
    }
    Txid::from_byte_array(bytes)
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
                Sequence(rng.next_u32())
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

#[test]
fn bitcoin_core_style_randomized_legacy_sighash_parity() {
    let mut rng = DeterministicRng::new(0x3b4d_6a2f_d915_7cbe);

    for i in 0..RANDOM_TESTS {
        let hash_type = rng.next_u32();
        let tx = random_transaction(&mut rng, (hash_type & 0x1f) == SIGHASH_SINGLE);
        // `bitcoin::SighashCache::legacy_signature_hash` expects callers to strip
        // OP_CODESEPARATOR before hashing (matching how interpreters prepare scriptCode).
        let script_code = remove_op_codeseparator(&random_script(&mut rng));
        let input_index = rng.range(tx.input.len());

        let old = legacy_signature_hash_old(&script_code, &tx, input_index, hash_type);
        let current = SighashCache::new(&tx)
            .legacy_signature_hash(input_index, &script_code, hash_type)
            .expect("legacy sighash calculation");

        assert_eq!(
            old.to_byte_array(),
            current.to_byte_array(),
            "legacy sighash mismatch at iteration {i} (input_index={input_index}, hash_type={hash_type:#x})"
        );
    }
}
