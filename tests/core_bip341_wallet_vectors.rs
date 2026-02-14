use bitcoin::{
    consensus as btc_consensus,
    consensus::Encodable,
    hashes::{sha256, Hash},
    hex::FromHex,
    key::{TapTweak, UntweakedPublicKey},
    secp256k1::{Keypair, Message, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{TapNodeHash, TapTweakHash},
    Amount, ScriptBuf, Transaction, TxOut, Witness,
};
use consensus::{verify_with_flags_detailed, Utxo, VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS};
use serde_json::Value;

const CORE_BIP341_WALLET_VECTORS: &str = include_str!("data/bip341_wallet_vectors.json");

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hash_serialized<'a, I, T>(items: I) -> sha256::Hash
where
    I: IntoIterator<Item = &'a T>,
    T: Encodable + 'a,
{
    let mut engine = sha256::Hash::engine();
    for item in items {
        item.consensus_encode(&mut engine)
            .expect("hash engine writes are infallible");
    }
    sha256::Hash::from_engine(engine)
}

fn hash_spent_amounts_single(prevouts: &[TxOut]) -> sha256::Hash {
    let mut engine = sha256::Hash::engine();
    for txout in prevouts {
        let value = txout.value.to_sat() as i64;
        value
            .consensus_encode(&mut engine)
            .expect("hash engine writes are infallible");
    }
    sha256::Hash::from_engine(engine)
}

fn parse_prevouts(case: &Value) -> Vec<TxOut> {
    let entries = case["given"]["utxosSpent"]
        .as_array()
        .expect("utxosSpent must be an array");
    entries
        .iter()
        .map(|entry| {
            let script_pubkey = Vec::from_hex(
                entry["scriptPubKey"]
                    .as_str()
                    .expect("utxo scriptPubKey must be hex"),
            )
            .expect("valid utxo scriptPubKey hex");
            let amount_sat = entry["amountSats"]
                .as_i64()
                .expect("utxo amountSats must be integer");
            assert!(amount_sat >= 0, "amountSats must be non-negative");
            TxOut {
                value: Amount::from_sat(amount_sat as u64),
                script_pubkey: ScriptBuf::from_bytes(script_pubkey),
            }
        })
        .collect()
}

fn parse_merkle_root(value: &Value) -> Option<TapNodeHash> {
    if value.is_null() {
        None
    } else {
        Some(
            TapNodeHash::from_slice(
                &Vec::from_hex(value.as_str().expect("merkleRoot must be hex string"))
                    .expect("valid merkleRoot hex"),
            )
            .expect("merkleRoot must be 32 bytes"),
        )
    }
}

fn parse_witness(value: &Value) -> Witness {
    let stack = value.as_array().expect("witness must be an array");
    let mut items = Vec::with_capacity(stack.len());
    for item in stack {
        let bytes = Vec::from_hex(item.as_str().expect("witness item must be hex"))
            .expect("valid witness item hex");
        items.push(bytes);
    }
    Witness::from_slice(&items)
}

#[test]
fn bitcoin_core_bip341_wallet_vectors() {
    let root: Value =
        serde_json::from_str(CORE_BIP341_WALLET_VECTORS).expect("bip341_wallet_vectors parses");
    let cases = root["keyPathSpending"]
        .as_array()
        .expect("keyPathSpending must be an array");
    assert!(!cases.is_empty(), "keyPathSpending vectors must not be empty");

    let secp = Secp256k1::new();

    for (case_index, case) in cases.iter().enumerate() {
        let raw_unsigned_tx = case["given"]["rawUnsignedTx"]
            .as_str()
            .expect("rawUnsignedTx must be hex");
        let tx_bytes = Vec::from_hex(raw_unsigned_tx).expect("rawUnsignedTx hex");
        let tx: Transaction = btc_consensus::deserialize(&tx_bytes).expect("unsigned tx decode");
        let prevouts = parse_prevouts(case);
        assert_eq!(
            prevouts.len(),
            tx.input.len(),
            "vector #{case_index}: prevout count mismatch"
        );

        let hash_prevouts = hash_serialized(tx.input.iter().map(|input| &input.previous_output));
        let hash_sequences = hash_serialized(tx.input.iter().map(|input| &input.sequence));
        let hash_outputs = hash_serialized(tx.output.iter());
        let hash_amounts = hash_spent_amounts_single(&prevouts);
        let hash_script_pubkeys = hash_serialized(prevouts.iter().map(|txout| &txout.script_pubkey));

        let intermediary = &case["intermediary"];
        assert_eq!(
            hash_prevouts.to_string(),
            intermediary["hashPrevouts"]
                .as_str()
                .expect("hashPrevouts must be string"),
            "vector #{case_index}: hashPrevouts mismatch"
        );
        assert_eq!(
            hash_sequences.to_string(),
            intermediary["hashSequences"]
                .as_str()
                .expect("hashSequences must be string"),
            "vector #{case_index}: hashSequences mismatch"
        );
        assert_eq!(
            hash_outputs.to_string(),
            intermediary["hashOutputs"]
                .as_str()
                .expect("hashOutputs must be string"),
            "vector #{case_index}: hashOutputs mismatch"
        );
        assert_eq!(
            hash_amounts.to_string(),
            intermediary["hashAmounts"]
                .as_str()
                .expect("hashAmounts must be string"),
            "vector #{case_index}: hashAmounts mismatch"
        );
        assert_eq!(
            hash_script_pubkeys.to_string(),
            intermediary["hashScriptPubkeys"]
                .as_str()
                .expect("hashScriptPubkeys must be string"),
            "vector #{case_index}: hashScriptPubkeys mismatch"
        );

        let input_vectors = case["inputSpending"]
            .as_array()
            .expect("inputSpending must be an array");
        for (input_vector_index, input_vector) in input_vectors.iter().enumerate() {
            let given = &input_vector["given"];
            let txin_index = given["txinIndex"]
                .as_u64()
                .expect("txinIndex must be integer") as usize;
            let hash_type_raw = given["hashType"]
                .as_i64()
                .expect("hashType must be integer");
            assert!(
                (0..=255).contains(&hash_type_raw),
                "vector #{case_index}/#{input_vector_index}: invalid hash type"
            );
            let hash_type = hash_type_raw as u8;
            let sighash_type = if hash_type == 0 {
                TapSighashType::Default
            } else {
                TapSighashType::from_consensus_u8(hash_type)
                    .expect("vector hash type must be valid TapSighashType")
            };

            let internal_privkey =
                Vec::from_hex(given["internalPrivkey"].as_str().expect("internalPrivkey hex"))
                    .expect("internalPrivkey must be hex");
            let secret_key = SecretKey::from_slice(&internal_privkey)
                .expect("internalPrivkey must decode as secp key");
            let keypair = Keypair::from_secret_key(&secp, &secret_key);
            let (internal_pubkey, _) = keypair.x_only_public_key();
            let internal_pubkey = UntweakedPublicKey::from(internal_pubkey);

            let intermediary = &input_vector["intermediary"];
            assert_eq!(
                to_hex(&internal_pubkey.serialize()),
                intermediary["internalPubkey"]
                    .as_str()
                    .expect("internalPubkey must be string"),
                "vector #{case_index}/#{input_vector_index}: internal pubkey mismatch"
            );

            let merkle_root = parse_merkle_root(&given["merkleRoot"]);
            let tweak = TapTweakHash::from_key_and_tweak(internal_pubkey, merkle_root);
            assert_eq!(
                tweak.to_string(),
                intermediary["tweak"].as_str().expect("tweak must be string"),
                "vector #{case_index}/#{input_vector_index}: tweak mismatch"
            );

            let mut cache = SighashCache::new(&tx);
            let sighash = cache
                .taproot_signature_hash(
                    txin_index,
                    &Prevouts::All(prevouts.as_slice()),
                    None,
                    None,
                    sighash_type,
                )
                .expect("taproot_signature_hash");
            assert_eq!(
                sighash.to_string(),
                intermediary["sigHash"].as_str().expect("sigHash must be string"),
                "vector #{case_index}/#{input_vector_index}: sigHash mismatch"
            );

            let tweaked_keypair = keypair.tap_tweak(&secp, merkle_root);
            let signature = secp.sign_schnorr_no_aux_rand(&Message::from(sighash), &tweaked_keypair.to_keypair());
            let mut signature_bytes = signature.as_ref().to_vec();
            if hash_type != 0 {
                signature_bytes.push(hash_type);
            }

            let expected_witness = input_vector["expected"]["witness"]
                .as_array()
                .expect("expected witness array");
            assert_eq!(
                expected_witness.len(),
                1,
                "vector #{case_index}/#{input_vector_index}: expected key-path witness with one element"
            );
            let expected_sig_hex = expected_witness[0]
                .as_str()
                .expect("expected witness signature must be hex");
            assert_eq!(
                to_hex(&signature_bytes),
                expected_sig_hex,
                "vector #{case_index}/#{input_vector_index}: expected signature mismatch"
            );

            let mut spending_tx = tx.clone();
            spending_tx.input[txin_index].script_sig = ScriptBuf::new();
            spending_tx.input[txin_index].witness = parse_witness(&input_vector["expected"]["witness"]);
            let spending_tx_bytes = btc_consensus::serialize(&spending_tx);

            let mut script_storage = Vec::with_capacity(prevouts.len());
            for prevout in &prevouts {
                script_storage.push(prevout.script_pubkey.as_bytes().to_vec());
            }
            let utxos: Vec<Utxo> = prevouts
                .iter()
                .zip(script_storage.iter())
                .map(|(prevout, script_bytes)| Utxo {
                    script_pubkey: script_bytes.as_ptr(),
                    script_pubkey_len: script_bytes.len() as u32,
                    value: prevout.value.to_sat() as i64,
                })
                .collect();

            verify_with_flags_detailed(
                prevouts[txin_index].script_pubkey.as_bytes(),
                prevouts[txin_index].value.to_sat(),
                &spending_tx_bytes,
                Some(&utxos),
                txin_index,
                VERIFY_P2SH | VERIFY_WITNESS | VERIFY_TAPROOT,
            )
            .unwrap_or_else(|err| {
                panic!(
                    "vector #{case_index}/#{input_vector_index}: key-path witness failed verification: {err:?}"
                )
            });
        }
    }
}
