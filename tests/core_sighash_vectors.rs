use bitcoin::{
    blockdata::script::Instruction, consensus as btc_consensus, hashes::Hash, hex::FromHex,
    opcodes::all, sighash::SighashCache, ScriptBuf, Transaction,
};
use serde_json::Value;

const CORE_SIGHASH_VECTORS: &str = include_str!("data/sighash.json");

fn to_core_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .rev()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn remove_op_codeseparator(script: &ScriptBuf) -> ScriptBuf {
    let bytes = script.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut cursor = 0usize;
    for item in script.instruction_indices() {
        let (index, instruction) = item.expect("sighash script must decode");
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

#[test]
fn bitcoin_core_sighash_vectors() {
    let vectors: Vec<Value> =
        serde_json::from_str(CORE_SIGHASH_VECTORS).expect("sighash.json parses");
    for case in vectors {
        let arr = match case.as_array() {
            Some(value) => value,
            None => continue,
        };
        if arr.len() == 1 && arr[0].is_string() {
            continue;
        }
        if arr.len() < 5 {
            continue;
        }

        let raw_tx = arr[0].as_str().expect("raw tx must be string");
        let raw_script = arr[1].as_str().expect("script must be string");
        let input_index = arr[2].as_i64().expect("input index must be integer") as usize;
        let hash_type = arr[3].as_i64().expect("hash type must be integer") as i32;
        let expected = arr[4].as_str().expect("expected hash must be string");

        let tx_bytes = Vec::from_hex(raw_tx).expect("raw tx hex");
        let tx: Transaction = btc_consensus::deserialize(&tx_bytes).expect("deserialize tx");
        let script_bytes = Vec::from_hex(raw_script).expect("script hex");
        let script_code = remove_op_codeseparator(&ScriptBuf::from_bytes(script_bytes));

        let cache = SighashCache::new(&tx);
        let got = cache
            .legacy_signature_hash(input_index, &script_code, hash_type as u32)
            .expect("legacy sighash");
        assert_eq!(
            to_core_hex(got.as_byte_array()),
            expected,
            "legacy sighash mismatch for hash_type={hash_type} input={input_index}"
        );
    }
}
